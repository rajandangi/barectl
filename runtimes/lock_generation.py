"""Generate, check and watch the runtime catalog lock with Nix.

docs/quality.md#runtime-catalog-lock. Runs only where Nix is installed (CI); the
application reads the committed lock through :mod:`runtimes.catalog`.

    python -m runtimes.lock_generation generate | check | drift | freshness \\
        | realise <architecture> | installer <architecture>
"""

import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .catalog import (
    ENTRY_NAME,
    FORMAT,
    LOCK_PATH,
    Architecture,
    Catalog,
    CatalogLockError,
    Installer,
    Kind,
    installer_url,
    load,
    parse,
)

PINS_PATH = Path(__file__).with_name("catalog_pins.json")
EXPRESSION_PATH = Path(__file__).with_name("catalog.nix")
CACHE = "https://cache.nixos.org"
# https://nix.dev/manual/nix/latest/command-ref/conf-file#conf-trusted-public-keys
CACHE_KEY = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
CHANNELS = "https://channels.nixos.org"
COMMITS = "https://api.github.com/repos/NixOS/nixpkgs/commits/"
FRESHNESS_LIMIT_DAYS = 14
_NIX_COMMAND = ("nix", "--extra-experimental-features", "nix-command")


class GenerationError(Exception):
    pass


@dataclass(frozen=True)
class Pin:
    nixpkgs: str
    # nix-prefetch-url --unpack of the commit's tarball.
    sha256: str
    entries: Mapping[str, tuple[Kind, str]]


@dataclass(frozen=True)
class Pins:
    nix: str
    # The channel whose head the lock's freshness is judged against.
    channel: str
    # Oldest first; the last is the current revision, the earlier ones only retire builds.
    revisions: tuple[Pin, ...]


class Nix(Protocol):
    def evaluate(self, pin: Pin, architecture: Architecture) -> Mapping[str, tuple[str, str]]:
        """Each entry's ``out`` store path and version."""

    def sizes(self, paths: Sequence[str]) -> Mapping[str, tuple[int, int]]:
        """Each path's closure size and closure download size on the binary cache."""

    def installer_sha256(self, version: str, architecture: Architecture) -> str: ...


class Runner(Protocol):
    def __call__(self, *command: str) -> str: ...


_NIX_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_CHANNEL = re.compile(r"nixos-[0-9]{2}\.[0-9]{2}")
_NIX32_SHA256 = re.compile(r"[0-9a-df-np-sv-z]{52}")
_ATTRIBUTE = re.compile(r"[A-Za-z_][A-Za-z0-9_'-]*(\.[A-Za-z_][A-Za-z0-9_'-]*)*")


def read_pins(text: str) -> Pins:
    try:
        data: object = json.loads(text)
    except ValueError as error:
        raise GenerationError(f"The pins are not JSON: {error}") from error
    if not isinstance(data, dict) or set(data) != {"nix", "channel", "revisions"}:
        raise GenerationError("The pins must have exactly the fields nix, channel and revisions.")
    nix, channel, revisions = data["nix"], data["channel"], data["revisions"]
    if not isinstance(nix, str) or not isinstance(revisions, list) or not revisions:
        raise GenerationError("The pins need a Nix version and at least one revision.")
    if _NIX_VERSION.fullmatch(nix) is None:
        raise GenerationError("The pinned Nix version is not a release number.")
    if not isinstance(channel, str) or _CHANNEL.fullmatch(channel) is None:
        raise GenerationError(f"{channel!r} is not a nixos release channel.")
    pins = Pins(nix, channel, tuple(_pin(item) for item in revisions))
    if len({pin.nixpkgs for pin in pins.revisions}) != len(pins.revisions):
        raise GenerationError("A nixpkgs revision is pinned more than once.")
    return pins


def _pin(value: object) -> Pin:
    if not isinstance(value, dict) or set(value) != {"nixpkgs", "sha256", "entries"}:
        raise GenerationError("Each revision must have exactly nixpkgs, sha256 and entries.")
    nixpkgs, sha256, entries = value["nixpkgs"], value["sha256"], value["entries"]
    if not isinstance(nixpkgs, str) or _COMMIT.fullmatch(nixpkgs) is None:
        raise GenerationError(f"{nixpkgs!r} is not a full nixpkgs commit hash.")
    if not isinstance(sha256, str) or _NIX32_SHA256.fullmatch(sha256) is None:
        raise GenerationError(f"nixpkgs {nixpkgs} needs its tarball's Nix base-32 SHA-256.")
    if not isinstance(entries, dict) or not entries:
        raise GenerationError(f"nixpkgs {nixpkgs} needs at least one entry.")
    pinned: dict[str, tuple[Kind, str]] = {}
    for name, entry in entries.items():
        if not isinstance(name, str) or ENTRY_NAME.fullmatch(name) is None:
            raise GenerationError(f"{name!r} is not a valid entry name.")
        if not isinstance(entry, dict) or set(entry) != {"kind", "attribute"}:
            raise GenerationError(f"{name} must have exactly kind and attribute.")
        kind, attribute = entry["kind"], entry["attribute"]
        if kind not in tuple(Kind) or not isinstance(attribute, str):
            raise GenerationError(f"{name} needs a known kind and an attribute path.")
        if _ATTRIBUTE.fullmatch(attribute) is None:
            raise GenerationError(f"{name}'s attribute is not an attribute path.")
        pinned[name] = (Kind(str(kind)), attribute)
    return Pin(nixpkgs, sha256, pinned)


def generate(pins: Pins, nix: Nix, previous: Catalog | None = None) -> str:
    """The lock text for ``pins``; refused if it would drop a build ``previous`` lists."""
    current = pins.revisions[-1]
    found: dict[tuple[Architecture, str], _Found] = {}
    for pin in pins.revisions:
        for architecture in Architecture:
            evaluated = nix.evaluate(pin, architecture)
            paths = [path for path, _ in evaluated.values()]
            if len(set(paths)) != len(paths):
                raise GenerationError(f"Two entries of {pin.nixpkgs} share a build.")
            for name, (kind, _) in pin.entries.items():
                path, version = evaluated[name]
                found[architecture, path] = _Found(name, kind, version, pin.nixpkgs)
    sizes = nix.sizes(sorted({path for _, path in found}))
    offered: dict[str, tuple[Kind, dict[Architecture, object]]] = {}
    retired: list[dict[str, object]] = []
    for (architecture, path), build in sorted(found.items()):
        fields: dict[str, object] = {
            "path": path,
            "version": build.version,
            "closure_size": sizes[path][0],
            "download_size": sizes[path][1],
        }
        if build.nixpkgs == current.nixpkgs:
            offered.setdefault(build.entry, (build.kind, {}))[1][architecture] = fields
        else:
            retired.append(
                {
                    "entry": build.entry,
                    "kind": build.kind,
                    "architecture": architecture,
                    "nixpkgs": build.nixpkgs,
                    **fields,
                }
            )
    lock = {
        "format": FORMAT,
        "nixpkgs": current.nixpkgs,
        "nix": {
            "version": pins.nix,
            "installers": {
                architecture: {
                    "url": installer_url(pins.nix, architecture),
                    "sha256": nix.installer_sha256(pins.nix, architecture),
                }
                for architecture in Architecture
            },
        },
        "entries": {
            name: {"kind": kind, "builds": builds} for name, (kind, builds) in offered.items()
        },
        "retired": retired,
    }
    text = json.dumps(lock, indent=2, sort_keys=True) + "\n"
    kept = {(build.architecture, build.path) for build in parse(text).builds}
    dropped = [
        build
        for build in (previous.builds if previous is not None else ())
        if (build.architecture, build.path) not in kept
    ]
    if dropped:
        names = ", ".join(f"{b.entry} {b.architecture} {b.path}" for b in dropped)
        raise GenerationError(
            f"Catalog builds are retired, never removed; keep their revision pinned: {names}"
        )
    return text


@dataclass(frozen=True)
class _Found:
    entry: str
    kind: Kind
    version: str
    nixpkgs: str


class CommandNix:
    """The installed Nix, evaluating nixpkgs and querying the official binary cache."""

    def evaluate(self, pin: Pin, architecture: Architecture) -> Mapping[str, tuple[str, str]]:
        attributes = {name: attribute for name, (_, attribute) in pin.entries.items()}
        output = _run(
            "nix-instantiate",
            "--eval",
            "--strict",
            "--json",
            str(EXPRESSION_PATH),
            "--argstr",
            "nixpkgs",
            pin.nixpkgs,
            "--argstr",
            "sha256",
            pin.sha256,
            "--argstr",
            "system",
            architecture,
            "--argstr",
            "entries",
            json.dumps(dict(attributes)),
        )
        data: object = json.loads(output)
        if not isinstance(data, dict) or set(data) != set(attributes):
            raise GenerationError(f"nixpkgs {pin.nixpkgs} did not evaluate every entry.")
        evaluated = {}
        for name, item in data.items():
            if not isinstance(item, dict):
                raise GenerationError(f"{name} did not evaluate to a build.")
            path, version = item.get("path"), item.get("version")
            if not isinstance(path, str) or not isinstance(version, str):
                raise GenerationError(f"{name} has no output path or version.")
            evaluated[str(name)] = (path, version)
        return evaluated

    def sizes(self, paths: Sequence[str]) -> Mapping[str, tuple[int, int]]:
        output = _run(
            *_NIX_COMMAND,
            "path-info",
            "--store",
            CACHE,
            "--json",
            "--json-format",
            "1",
            "--closure-size",
            *paths,
        )
        data: object = json.loads(output)
        if not isinstance(data, dict):
            raise GenerationError("nix path-info did not report the paths.")
        sizes = {}
        for path in paths:
            info = data.get(path)
            closure = info.get("closureSize") if isinstance(info, dict) else None
            download = info.get("closureDownloadSize") if isinstance(info, dict) else None
            if not isinstance(closure, int) or not isinstance(download, int):
                raise GenerationError(f"{CACHE} has no complete closure for {path}.")
            sizes[path] = (closure, download)
        return sizes

    def installer_sha256(self, version: str, architecture: Architecture) -> str:
        url = installer_url(version, architecture)
        with urllib.request.urlopen(url, timeout=300) as response:  # noqa: S310 - the official release URL
            body: bytes = response.read()
        return hashlib.sha256(body).hexdigest()


def _run(*command: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed Nix commands with validated arguments
        command, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        words = [word for word in command[:5] if not word.startswith("-")]
        reason = (result.stderr.strip().splitlines() or ["no error output"])[-1]
        raise GenerationError(f"{' '.join(w for w in words if w != 'nix-command')}: {reason}")
    return result.stdout


def drift(catalog: Catalog) -> list[str]:
    """One line per locked build: whether its closure still has signed metadata on the cache."""
    lines = []
    for build in sorted(catalog.builds, key=lambda b: (b.entry, b.architecture, b.path)):
        label = f"{build.entry} {build.architecture} {build.path}"
        try:
            _run(*_NIX_COMMAND, "path-info", "--store", CACHE, "--recursive", build.path)
            _run(
                *_NIX_COMMAND,
                "store",
                "verify",
                "--store",
                CACHE,
                "--no-contents",
                "--recursive",
                "--option",
                "trusted-public-keys",
                CACHE_KEY,
                build.path,
            )
        except GenerationError as error:
            lines.append(f"{label}: no signed metadata ({error})")
        else:
            lines.append(f"{label}: signed")
    return lines


def freshness(pins: Pins, lock: Catalog, fetch: Callable[[str], str]) -> str:
    """The lock's age against the pinned channel's head, from channel and commit
    metadata only; refused when the lock falls behind by more than the limit."""
    head = _fetched(f"{CHANNELS}/{pins.channel}/git-revision", fetch).strip()
    if _COMMIT.fullmatch(head) is None:
        raise GenerationError(f"The {pins.channel} channel did not name a revision.")
    behind = (_committed(head, fetch) - _committed(lock.nixpkgs, fetch)).days
    if behind <= 0:
        return f"The lock's nixpkgs {lock.nixpkgs} is not behind {pins.channel} head {head}."
    summary = (
        f"The lock's nixpkgs {lock.nixpkgs} is {behind} days behind {pins.channel} head {head}."
    )
    if behind > FRESHNESS_LIMIT_DAYS:
        raise GenerationError(
            f"{summary} More than {FRESHNESS_LIMIT_DAYS} days behind: pin a newer revision."
        )
    return summary


def _fetched(url: str, fetch: Callable[[str], str]) -> str:
    try:
        return fetch(url)
    except OSError as error:
        raise GenerationError(f"{url} did not answer: {error}") from error


def _committed(revision: str, fetch: Callable[[str], str]) -> datetime:
    try:
        data: object = json.loads(_fetched(f"{COMMITS}{revision}", fetch))
    except ValueError as error:
        raise GenerationError(f"nixpkgs {revision} has no commit record: {error}") from error
    date = None
    if isinstance(data, dict) and data.get("sha") == revision:
        record = data.get("commit")
        if isinstance(record, dict):
            committer = record.get("committer")
            if isinstance(committer, dict):
                raw = committer.get("date")
                if isinstance(raw, str):
                    date = raw
    if date is None:
        raise GenerationError(f"nixpkgs {revision} has no commit record.")
    try:
        return datetime.fromisoformat(date)
    except ValueError as error:
        raise GenerationError(f"nixpkgs {revision} has no parsable commit date: {date}.") from error


def realise(
    catalog: Catalog,
    architecture: Architecture,
    run: Runner,
    now: Callable[[], float],
) -> str:
    """One line per offered build plus totals, after realising the catalog the way a
    server does: ``nix-store --realise`` with ``max-jobs = 0``, so nothing is built."""
    builds = catalog.offered(architecture)
    paths = [b.path for b in builds]
    started = now()
    run(
        "nix-store",
        "--realise",
        "--option",
        "max-jobs",
        "0",
        "--option",
        "fallback",
        "false",
        *paths,
    )
    seconds = now() - started
    requisites = _json_object(
        run(
            *_NIX_COMMAND,
            "path-info",
            "--recursive",
            "--json",
            "--json-format",
            "1",
            "--size",
            *paths,
        )
    )
    unpacked = sum(
        _reported(info, "narSize", f"The store did not report the size of {path}.")
        for path, info in requisites.items()
    )
    closures = _json_object(
        run(
            *_NIX_COMMAND,
            "path-info",
            "--store",
            CACHE,
            "--json",
            "--json-format",
            "1",
            "--closure-size",
            *paths,
        )
    )
    download = sum(
        _reported(
            closures.get(path),
            "closureDownloadSize",
            f"{CACHE} has no complete closure for {path}.",
        )
        for path in paths
    )
    lines = [f"{build.entry} {build.version} {build.path}: realised" for build in builds]
    lines.append(
        f"{len(builds)} builds, {len(requisites)} store paths, "
        f"{_mib(unpacked)} unpacked, {_mib(download)} of entry downloads, {seconds:.0f} s, "
        "no derivations built (max-jobs = 0, fallback = false)"
    )
    return "".join(f"{line}\n" for line in lines)


def _mib(size: int) -> str:
    return f"{size / (1024 * 1024):.0f} MiB"


def _reported(info: object, field: str, refusal: str) -> int:
    value = info.get(field) if isinstance(info, dict) else None
    if not isinstance(value, int):
        raise GenerationError(refusal)
    return value


def _json_object(text: str) -> dict[str, object]:
    try:
        data: object = json.loads(text)
    except ValueError as error:
        raise GenerationError(f"Nix did not report JSON: {error}") from error
    if not isinstance(data, dict):
        raise GenerationError("Nix did not report a JSON object.")
    return {str(key): item for key, item in data.items()}


def check(pins: Pins, nix: Nix, committed: str, base: str | None) -> str | None:
    """Why ``committed`` is not the lock ``pins`` generate, or ``None`` when it is.

    Retirement is judged against the base branch's lock, so a change that drops a revision
    and regenerates is still refused.
    """
    text = generate(pins, nix, parse(base) if base is not None else None)
    if text == committed:
        return None
    return "".join(
        difflib.unified_diff(
            committed.splitlines(keepends=True),
            text.splitlines(keepends=True),
            "committed",
            "generated",
        )
    )


def trusted_installer(
    lock: Catalog,
    base: Catalog | None,
    architecture: Architecture,
    published: Callable[[str], str],
) -> Installer:
    """The lock's Nix installer, once its digest is the base lock's or, for a new Nix
    release, the one ``published`` returns from the release's ``.sha256`` URL."""
    installer = lock.installer(architecture)
    before = base.installer(architecture) if base is not None else None
    if before is not None and before.version == installer.version:
        expected = before.sha256
    else:
        expected = published(f"{installer.url}.sha256").strip()
    if installer.sha256 != expected:
        raise GenerationError(
            f"The locked Nix {installer.version} installer digest for {architecture} is not "
            f"the trusted one ({expected})."
        )
    return installer


def base_lock() -> str | None:
    """The catalog lock on the base branch, ``None`` when that branch has none yet."""
    ref = f"origin/{os.environ.get('GITHUB_BASE_REF') or 'main'}"
    if _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}") is None:
        raise GenerationError(f"{ref} is not fetched; the lock is judged against it.")
    return _git("show", f"{ref}:runtimes/{LOCK_PATH.name}")


def _git(*arguments: str) -> str | None:
    command = ("git", *arguments)
    try:
        result = subprocess.run(  # noqa: S603 - fixed Git reads
            command, capture_output=True, text=True, check=False
        )
    except OSError:
        return None
    return result.stdout if result.returncode == 0 else None


def _published(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - the official release URL
        body: bytes = response.read()
    return body.decode("ascii", errors="replace")


_USAGE = (
    "usage: python -m runtimes.lock_generation generate|check|drift|freshness"
    "|realise <architecture>|installer <architecture>\n"
)


def main(arguments: Sequence[str]) -> int:
    command, *rest = (*arguments, "")
    try:
        match command, rest:
            case "drift", [""]:
                lines = drift(load())
                sys.stdout.write("".join(f"{line}\n" for line in lines))
                return 0 if all(line.endswith(": signed") for line in lines) else 1
            case "freshness", [""]:
                sys.stdout.write(f"{freshness(_pins(), load(), _published)}\n")
                return 0
            case "realise", [architecture, ""] if architecture in tuple(Architecture):
                sys.stdout.write(realise(load(), Architecture(architecture), _run, time.monotonic))
                return 0
            case "installer", [architecture, ""] if architecture in tuple(Architecture):
                base = base_lock()
                installer = trusted_installer(
                    load(),
                    parse(base) if base is not None else None,
                    Architecture(architecture),
                    _published,
                )
                sys.stdout.write(f"{installer.url} {installer.sha256}\n")
                return 0
            case "generate", [""]:
                committed = LOCK_PATH.read_text(encoding="utf-8") if LOCK_PATH.exists() else None
                previous = parse(committed) if committed is not None else None
                text = generate(_pins(), CommandNix(), previous)
                LOCK_PATH.write_text(text, encoding="utf-8")
                return 0
            case "check", [""]:
                difference = check(
                    _pins(), CommandNix(), LOCK_PATH.read_text(encoding="utf-8"), base_lock()
                )
                if difference is None:
                    sys.stdout.write("The catalog lock matches its pins.\n")
                    return 0
                sys.stdout.write(difference)
                sys.stderr.write(
                    "The committed catalog lock differs from the one its pins generate.\n"
                )
                return 1
            case _:
                sys.stderr.write(_USAGE)
                return 2
    except (GenerationError, CatalogLockError) as error:
        sys.stderr.write(f"{error}\n")
        return 1


def _pins() -> Pins:
    return read_pins(PINS_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
