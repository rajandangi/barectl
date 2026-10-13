"""Byte-exact local copies of the upstreams a build needs, and their manifest.

docs/quality.md#native-layer describes the mirror. Every entry is one file fetched from a
real host and served under that host's real name, so the signatures stay the upstreams'
own; nothing in a scenario reaches the internet. The manifest holds each file's SHA-256,
so a fetch verifies it and the drift job can tell when upstream changed.

The mirror is filled only by ``python -m disposable.mirror fetch`` (or ``generate`` to write
the manifest) on a host with internet; scenarios read it offline.
"""

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

REPOSITORY = Path(__file__).resolve().parent.parent
MANIFEST = REPOSITORY / "docker" / "disposable-server" / "mirror-manifest.json"
CATALOG_LOCK = REPOSITORY / "runtimes" / "catalog_lock.json"
FORMAT = 1
CACHE_HOST = "cache.nixos.org"
ARCHITECTURES = ("aarch64-linux", "x86_64-linux")
_DOCKER_TO_LOCK = {"aarch64": "aarch64-linux", "arm64": "aarch64-linux",
                   "x86_64": "x86_64-linux", "amd64": "x86_64-linux"}  # fmt: skip
# Ubuntu serves the amd64 release pocket from archive.ubuntu.com and every other
# architecture from the ports host. Only the frozen release pocket is mirrored: the
# -updates and -security pockets are recomputed with every publication, so their bytes
# cannot be a stable manifest entry (spike P6.1, docs/quality.md#native-layer).
_UBUNTU = {
    "x86_64-linux": (("archive.ubuntu.com", "ubuntu", ("resolute",)),),
    "aarch64-linux": (("ports.ubuntu.com", "ubuntu-ports", ("resolute",)),),
}
# A store path's narinfo is named by its hash, not its full name.
_STORE_NAME = re.compile(r"^[a-z0-9]{32}-(?P<name>.+)$")


class MirrorError(Exception):
    """A mirror entry could not be fetched or verified."""


class _StoreFn(Protocol):
    def __call__(
        self, host: str, path: str, architecture: str, expected: str | None = None
    ) -> bytes: ...


@dataclass(frozen=True)
class Entry:
    """One upstream file: where it lives, what host serves it and its SHA-256."""

    host: str
    path: str
    sha256: str
    size: int
    architecture: str

    @property
    def url(self) -> str:
        return f"https://{self.host}/{self.path}"

    def document(self) -> dict[str, object]:
        return {
            "host": self.host,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "architecture": self.architecture,
        }


@dataclass(frozen=True)
class Manifest:
    entries: tuple[Entry, ...]

    def dumps(self) -> str:
        document = {"format": FORMAT, "entries": [entry.document() for entry in self.entries]}
        return json.dumps(document, indent=1, sort_keys=True) + "\n"

    @classmethod
    def parse(cls, text: str) -> Manifest:
        document = _object(json.loads(text), "the manifest")
        if document.get("format") != FORMAT:
            raise MirrorError(f"The mirror manifest is not in format {FORMAT}.")
        raw = document.get("entries")
        if not isinstance(raw, list):
            raise MirrorError("The mirror manifest lists no entries.")
        return cls(tuple(_entry(value) for value in raw))

    def architectures(self) -> tuple[str, ...]:
        return tuple(sorted({entry.architecture for entry in self.entries}))

    def hosts(self) -> tuple[str, ...]:
        return tuple(sorted({entry.host for entry in self.entries}))

    def for_architecture(self, architecture: str) -> tuple[Entry, ...]:
        return tuple(entry for entry in self.entries if entry.architecture == architecture)


def _entry(value: object) -> Entry:
    fields = _object(value, "a mirror entry")
    try:
        return Entry(
            host=_text(fields, "host"),
            path=_text(fields, "path"),
            sha256=_text(fields, "sha256"),
            size=_integer(fields, "size"),
            architecture=_text(fields, "architecture"),
        )
    except KeyError as missing:
        raise MirrorError(f"A mirror entry is missing {missing}.") from None


def _object(value: object, what: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise MirrorError(f"The document of {what} is not a JSON object.")
    return value


def _text(fields: Mapping[str, object], key: str) -> str:
    value = fields[key]
    if not isinstance(value, str) or not value:
        raise MirrorError(f"A mirror entry's {key} is missing or not text.")
    return value


def _integer(fields: Mapping[str, object], key: str) -> int:
    value = fields[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise MirrorError(f"A mirror entry's {key} is not a whole number.")
    return value


def load() -> Manifest:
    return Manifest.parse(MANIFEST.read_text(encoding="utf-8"))


def lock_architecture(machine: str) -> str:
    """The catalog lock's architecture name for a server's ``uname -m``."""
    if machine not in _DOCKER_TO_LOCK:
        raise MirrorError(f"Unknown machine architecture {machine!r}.")
    return _DOCKER_TO_LOCK[machine]


def catalog_installer(architecture: str) -> tuple[str, str]:
    """The pinned Nix installer's URL and SHA-256 for ``architecture``."""
    lock = _object(json.loads(CATALOG_LOCK.read_text(encoding="utf-8")), "the catalog lock")
    installers = _installers(lock, architecture)
    if not installers:
        raise MirrorError(f"The catalog lock lists no installer for {architecture}.")
    return _text(installers[0], "url"), _text(installers[0], "sha256")


def catalog_store_paths(architecture: str) -> list[str]:
    """The catalog lock's offered store paths for ``architecture``."""
    lock = _object(json.loads(CATALOG_LOCK.read_text(encoding="utf-8")), "the catalog lock")
    return _catalog_paths(lock, architecture)


def cache_root() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    directory = root / "barectl" / "native" / "mirror"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def host_architecture() -> str:
    """The lock's architecture name for this Docker host, from ``docker info``."""
    docker_arch = os.environ.get("BARECTL_MIRROR_ARCH")
    if not docker_arch:
        completed = subprocess.run(
            ["docker", "info", "--format", "{{.Architecture}}"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        docker_arch = completed.stdout.strip()
    if docker_arch not in _DOCKER_TO_LOCK:
        raise MirrorError(f"Unknown Docker architecture {docker_arch!r}.")
    return _DOCKER_TO_LOCK[docker_arch]


def download(url: str, *, attempts: int = 3) -> bytes:
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310
                body: bytes = response.read()
                return body
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            last = error
            time.sleep(0.5 * (attempt + 1))
    raise MirrorError(f"Could not fetch {url}: {last}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Generating the manifest (needs the internet; run by a maintainer or the drift job).


def generate(root: Path) -> Manifest:
    """Walk every catalog closure and Ubuntu pocket, download the files and write the manifest."""
    lock = _object(json.loads(CATALOG_LOCK.read_text(encoding="utf-8")), "the catalog lock")
    storer: dict[tuple[str, str, str], Entry] = {}

    def store(host: str, path: str, architecture: str, expected: str | None = None) -> bytes:
        data = download(f"https://{host}/{path}")
        digest = sha256(data)
        if expected is not None and digest != expected:
            raise MirrorError(f"{host}/{path} has SHA-256 {digest}, expected {expected}.")
        _write(root, host, path, data)
        storer[(host, path, architecture)] = Entry(host, path, digest, len(data), architecture)
        return data

    for architecture in ARCHITECTURES:
        for store_path in _catalog_paths(lock, architecture):
            _walk(store_path, architecture, store)
        for installer in _installers(lock, architecture):
            url = _text(installer, "url")
            host, _, path = url.partition("://")[2].partition("/")
            store(host, path, architecture, expected=_text(installer, "sha256"))
        # Nix asks the cache for this before anything else.
        store(CACHE_HOST, "nix-cache-info", architecture)
        for host, tree, suites in _UBUNTU[architecture]:
            for suite in suites:
                store(host, f"{tree}/dists/{suite}/InRelease", architecture)

    manifest = Manifest(tuple(sorted(storer.values(), key=lambda entry: (entry.host, entry.path))))
    MANIFEST.write_text(manifest.dumps(), encoding="utf-8")
    return manifest


def _catalog_paths(lock: Mapping[str, object], architecture: str) -> list[str]:
    entries = _object(lock.get("entries"), "the catalog entries")
    paths: list[str] = []
    for value in entries.values():
        entry = _object(value, "a catalog entry")
        builds = _object(entry.get("builds"), "a catalog entry's builds")
        build = builds.get(architecture)
        if build is not None:
            paths.append(_text(_object(build, "a catalog build"), "path"))
    return paths


def _installers(lock: Mapping[str, object], architecture: str) -> list[Mapping[str, object]]:
    nix = _object(lock.get("nix"), "the catalog's Nix release")
    installers = _object(nix.get("installers"), "the catalog's installers")
    build = installers.get(architecture)
    return [] if build is None else [_object(build, "an installer")]


def _walk(top: str, architecture: str, store: _StoreFn) -> None:
    """Download a store path's closure: each narinfo and the NAR it names, byte for byte."""
    seen: set[str] = set()
    queue = deque([top])
    while queue:
        store_path = queue.popleft()
        if store_path in seen:
            continue
        seen.add(store_path)
        name = store_path.rsplit("/", 1)[-1]
        match = _STORE_NAME.match(name)
        if match is None:
            raise MirrorError(f"Unrecognized store path {store_path}.")
        narinfo = store(CACHE_HOST, f"{name.partition('-')[0]}.narinfo", architecture)
        fields = _narinfo_fields(narinfo)
        nar_path = fields.get("URL")
        if nar_path is None:
            raise MirrorError(f"The narinfo of {store_path} names no NAR.")
        store(CACHE_HOST, nar_path, architecture)
        for reference in fields.get("References", "").split():
            queue.append(f"/nix/store/{reference}")


def _narinfo_fields(data: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in data.decode("utf-8", "replace").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip()] = value.strip()
    return fields


def _write(root: Path, host: str, path: str, data: bytes) -> None:
    destination = root / host / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and sha256(destination.read_bytes()) == sha256(data):
        return
    destination.write_bytes(data)


# Fetching and checking against the committed manifest (no manifest generation).


def fetch(manifest: Manifest, root: Path, *, architectures: Sequence[str] | None = None) -> int:
    """Download every manifest entry not already stored, verifying its SHA-256."""
    wanted = None if architectures is None else set(architectures)
    entries = [
        entry for entry in manifest.entries if wanted is None or entry.architecture in wanted
    ]

    def store(entry: Entry) -> None:
        destination = root / entry.host / entry.path
        if destination.exists() and sha256(destination.read_bytes()) == entry.sha256:
            return
        data = download(entry.url)
        digest = sha256(data)
        if digest != entry.sha256:
            raise MirrorError(
                f"{entry.url} has SHA-256 {digest}, expected {entry.sha256}; "
                "upstream changed or the manifest is stale."
            )
        if len(data) != entry.size:
            raise MirrorError(f"{entry.url} is {len(data)} bytes, expected {entry.size}.")
        _write(root, entry.host, entry.path, data)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for _ in pool.map(store, entries):
            pass
    return len(entries)


def drift(manifest: Manifest) -> list[str]:
    """The entries whose upstream bytes no longer match the manifest, by URL."""
    changed: list[str] = []
    for entry in manifest.entries:
        try:
            digest = sha256(download(entry.url))
        except MirrorError as error:
            changed.append(f"{entry.url}: {error}")
            continue
        if digest != entry.sha256:
            changed.append(f"{entry.url}: upstream {digest}, manifest {entry.sha256}")
    return changed


# The fixture CA the servers and mirrors trust (docs/quality.md#native-layer).

FIXTURE_CA = "barectl-native-fixture-ca"
CA_CERTIFICATE = "ca.crt"
CA_KEY = "ca.key"


def fixture_ca() -> tuple[Path, Path]:
    """The harness's own CA certificate and key, created once and reused."""
    directory = cache_root() / FIXTURE_CA
    certificate = directory / CA_CERTIFICATE
    key = directory / CA_KEY
    if not certificate.exists() or not key.exists():
        directory.mkdir(parents=True, exist_ok=True)
        _openssl(
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", str(key), "-out", str(certificate), "-days", "3650",
            "-subj", f"/CN={FIXTURE_CA}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
        )  # fmt: skip
    return certificate, key


def mirror_certificate(hosts: Iterable[str]) -> tuple[Path, Path]:
    """A leaf certificate, signed by the fixture CA, valid for the mirrored host names."""
    names = tuple(sorted(set(hosts)))
    directory = cache_root() / f"mirror-{sha256(' '.join(names).encode())[:12]}"
    certificate = directory / "mirror.crt"
    key = directory / "mirror.key"
    if not certificate.exists() or not key.exists():
        directory.mkdir(parents=True, exist_ok=True)
        ca_certificate, ca_key = fixture_ca()
        san = ",".join(f"DNS:{name}" for name in names)
        _openssl(
            "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", str(key), "-out", str(directory / "mirror.csr"),
            "-subj", "/CN=cache.nixos.org",
        )  # fmt: skip
        _openssl(
            "x509", "-req", "-sha256", "-in", str(directory / "mirror.csr"),
            "-CA", str(ca_certificate), "-CAkey", str(ca_key), "-set_serial", "0x01",
            "-days", "365", "-extfile", "/dev/stdin", "-out", str(certificate),
            stdin=(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                "subjectKeyIdentifier=hash\n"
                "authorityKeyIdentifier=keyid:always\n"
                f"subjectAltName={san}\n"
            ),
        )  # fmt: skip
    return certificate, key


def _openssl(*arguments: str, stdin: str | None = None) -> None:
    completed = subprocess.run(  # noqa: S603 - fixed OpenSSL arguments
        ["openssl", *arguments],  # noqa: S607 - OpenSSL on PATH
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        raise MirrorError(f"openssl {arguments[0]}: {completed.stderr.strip()}")


# The entry point.


def _print_drift(changed: Sequence[str]) -> int:
    if not changed:
        print("mirror: every manifest hash matches upstream.")  # noqa: T201
        return 0
    print(f"mirror: {len(changed)} entries drifted from upstream:")  # noqa: T201
    for line in changed:
        print(f"  {line}")  # noqa: T201
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="mirror", description=__doc__)
    parser.add_argument("command", choices=("generate", "fetch", "drift"))
    parser.add_argument("--all-architectures", action="store_true", help="not just this host's")
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    root = cache_root()
    if options.command == "generate":
        manifest = generate(root)
        print(f"mirror: wrote {MANIFEST} with {len(manifest.entries)} entries.")  # noqa: T201
        return 0
    manifest = load()
    if options.command == "drift":
        return _print_drift(drift(manifest))
    architectures = None if options.all_architectures else [host_architecture()]
    count = fetch(manifest, root, architectures=architectures)
    print(f"mirror: verified {count} entries under {root}.")  # noqa: T201
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
