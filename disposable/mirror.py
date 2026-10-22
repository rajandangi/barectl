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
import tarfile
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
PINS = REPOSITORY / "docker" / "disposable-server" / "pins.json"
CATALOG_LOCK = REPOSITORY / "runtimes" / "catalog_lock.json"
FIXTURE_APP = REPOSITORY / "docker" / "disposable-server" / "fixtures" / "laravel-app"
COMPOSER_LOCK = FIXTURE_APP / "composer.lock"
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
# Phase B fixtures (docs/quality.md#native-layer). snapshot.ubuntu.com publishes an
# immutable archive state, so its release, -updates and -security pockets can be mirrored
# byte-exactly with one SHA-256 per file, unlike the live archive the pockets above come
# from. The server is pointed at the snapshot under its real host name.
SNAPSHOT_HOST = "snapshot.ubuntu.com"
SNAPSHOT_TIMESTAMP = "20261017T000000Z"
SNAPSHOT_ROOT = f"ubuntu/{SNAPSHOT_TIMESTAMP}"
SNAPSHOT_SUITES = ("resolute", "resolute-updates", "resolute-security")
SNAPSHOT_COMPONENT = "main"
# The database engines and Git #356 names, installed from the Ubuntu 26.04 archive.
UBUNTU_FIXTURES = ("mariadb-server", "postgresql", "git")
_DEB_ARCH = {"x86_64-linux": "amd64", "aarch64-linux": "arm64"}
_DOCKER_PLATFORM = {"x86_64-linux": "linux/amd64", "aarch64-linux": "linux/arm64"}
_IMAGETOOLS_FORMAT = (
    "{{range .Manifest.Manifests}}{{.Platform.OS}}/{{.Platform.Architecture}}={{.Digest}}\n{{end}}"
)
# The local ACME server of #375: Pebble, run on the lane and trusted through Caddy's
# acme_ca and acme_ca_root. The release carries one static binary per architecture and the
# fixed test certificates from the tag, so nothing is fetched at scenario time.
PEBBLE_VERSION = "2.10.1"
PEBBLE_RELEASE_HOST = "github.com"
PEBBLE_RAW_HOST = "raw.githubusercontent.com"
_PEBBLE_ASSET = "letsencrypt/pebble/releases/download/{version}/pebble-linux-{arch}.tar.gz"
_PEBBLE_CERTS = (
    "test/certs/pebble.minica.pem",
    "test/certs/localhost/cert.pem",
    "test/certs/localhost/key.pem",
)
# The pinned WordPress release of #356.
WORDPRESS_VERSION = "7.1.3"
WORDPRESS_HOST = "downloads.wordpress.org"
WORDPRESS_ARCHIVE = f"release/wordpress-{WORDPRESS_VERSION}.zip"
# WP-CLI's ``core verify-checksums`` reads this endpoint; the mirror serves the response as
# the directory's index so the query string WP-CLI adds still reaches it (Phase B #381).
WORDPRESS_API_HOST = "api.wordpress.org"
WORDPRESS_CHECKSUMS = "core/checksums/1.0/index.html"
WORDPRESS_CHECKSUMS_SOURCE = f"core/checksums/1.0/?version={WORDPRESS_VERSION}&locale=en_US"
# A store path's narinfo is named by its hash, not its full name.
_STORE_NAME = re.compile(r"^[a-z0-9]{32}-(?P<name>.+)$")
# Resolves the fixture packages against the snapshot inside the pinned base image. Docker
# runs the upstream apt resolver, so the manifest lists exactly the packages apt chooses
# (AGENTS.md "Reuse existing tools first"); ca-certificates is installed from the live
# archive over HTTP first, because the base image trusts no HTTPS authority yet.
_APT_RESOLVE = """\
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y --no-install-recommends ca-certificates >/dev/null 2>&1
cat >/etc/apt/sources.list.d/barectl-snapshot.sources <<'EOF'
Types: deb
URIs: https://{host}/{root}
Suites: {suites}
Components: {component}
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
rm -f /etc/apt/sources.list.d/ubuntu.sources
apt-get update -qq >/dev/null 2>&1
apt-get install -y --print-uris --no-install-recommends {packages} 2>/dev/null
"""


class MirrorError(Exception):
    """A mirror entry could not be fetched or verified."""


class _StoreFn(Protocol):
    def __call__(
        self,
        host: str,
        path: str,
        architecture: str,
        expected: str | None = None,
        *,
        source: str | None = None,
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


def base_image(release: str = "26.04") -> str:
    """The pinned Ubuntu base image for ``release``, by digest (``pins.json``)."""
    pins = json.loads(PINS.read_text(encoding="utf-8"))
    value = pins.get(f"ubuntu-{release}")
    if not isinstance(value, str):
        raise MirrorError(f"pins.json has no digest for ubuntu-{release}.")
    return value


def platform_image(architecture: str) -> str:
    """The pinned base image's manifest digest for one architecture.

    ``pins.json`` holds the multi-architecture index digest, which Docker refuses to run
    with an explicit ``--platform``; resolving the platform manifest keeps generation on
    the exact pinned image.
    """
    image = base_image()
    repository = image.partition("@")[0]
    command = [
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        image,
        "--format",
        _IMAGETOOLS_FORMAT,
    ]
    completed = subprocess.run(  # noqa: S603 - the harness's own Docker
        command, capture_output=True, text=True, timeout=300, check=False
    )
    if completed.returncode != 0:
        raise MirrorError(f"Resolving {image} failed: {completed.stderr.strip()[-200:]}")
    for line in completed.stdout.splitlines():
        name, _, digest = line.partition("=")
        if name == _DOCKER_PLATFORM[architecture]:
            return f"{repository}@{digest}"
    raise MirrorError(f"{image} has no {_DOCKER_PLATFORM[architecture]} manifest.")


def apt_sources(timestamp: str = SNAPSHOT_TIMESTAMP) -> str:
    """The deb822 source the fixture host uses to reach the mirrored snapshot."""
    return (
        "Types: deb\n"
        f"URIs: https://{SNAPSHOT_HOST}/ubuntu/{timestamp}\n"
        f"Suites: {' '.join(SNAPSHOT_SUITES)}\n"
        f"Components: {SNAPSHOT_COMPONENT}\n"
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
    )


def generate(root: Path, architectures: tuple[str, ...] | None = None) -> Manifest:
    """Download every catalog closure and fixture, verify it and write the manifest.

    An entry already in the manifest whose file is present in the cache is reused without
    another download, so adding a fixture only fetches the new files. ``drift`` is the
    check that the reused bytes still match upstream. ``architectures`` limits the download
    to some architectures and keeps the manifest's other entries as they are.
    """
    lock = _object(json.loads(CATALOG_LOCK.read_text(encoding="utf-8")), "the catalog lock")
    known = {_key(entry): entry for entry in _existing()}
    storer: dict[tuple[str, str, str], Entry] = {}

    def store(
        host: str,
        path: str,
        architecture: str,
        expected: str | None = None,
        *,
        source: str | None = None,
    ) -> bytes:
        key = (host, path, architecture)
        entry = known.get(key)
        cached = root / host / path
        if (
            entry is not None
            and cached.exists()
            and (expected is None or entry.sha256 == expected)
            and sha256(cached.read_bytes()) == entry.sha256
        ):
            storer[key] = entry
            return cached.read_bytes()
        data = download(f"https://{host}/{source or path}")
        digest = sha256(data)
        if expected is not None and digest != expected:
            raise MirrorError(f"{host}/{path} has SHA-256 {digest}, expected {expected}.")
        _write(root, host, path, data)
        storer[key] = Entry(host, path, digest, len(data), architecture)
        return data

    targets = ARCHITECTURES if architectures is None else architectures
    for architecture in targets:
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
        _snapshot_entries(architecture, store)
        _pebble_entries(architecture, store)
        _wordpress_entries(architecture, store)
        _composer_entries(architecture, store)

    kept = [entry for entry in known.values() if entry.architecture not in targets]
    manifest = Manifest(
        tuple(sorted((*storer.values(), *kept), key=lambda entry: (entry.host, entry.path)))
    )
    MANIFEST.write_text(manifest.dumps(), encoding="utf-8")
    return manifest


def _key(entry: Entry) -> tuple[str, str, str]:
    return (entry.host, entry.path, entry.architecture)


def _existing() -> tuple[Entry, ...]:
    return Manifest.parse(MANIFEST.read_text(encoding="utf-8")).entries if MANIFEST.exists() else ()


def _snapshot_entries(architecture: str, store: _StoreFn) -> None:
    """The mirrored snapshot's indices and the fixture packages' resolved closure."""
    deb_arch = _DEB_ARCH[architecture]
    for suite in SNAPSHOT_SUITES:
        store(SNAPSHOT_HOST, f"{SNAPSHOT_ROOT}/dists/{suite}/InRelease", architecture)
        for name in ("Packages.xz", "Packages.gz"):
            store(
                SNAPSHOT_HOST,
                f"{SNAPSHOT_ROOT}/dists/{suite}/{SNAPSHOT_COMPONENT}/binary-{deb_arch}/{name}",
                architecture,
            )
        # apt fetches the command-not-found index by default; a missing one fails update.
        store(
            SNAPSHOT_HOST,
            f"{SNAPSHOT_ROOT}/dists/{suite}/{SNAPSHOT_COMPONENT}/cnf/Commands-{deb_arch}.xz",
            architecture,
        )
    for url in _package_urls(architecture):
        host, _, path = url.partition("://")[2].partition("/")
        store(host, path, architecture)


def _package_urls(architecture: str) -> list[str]:
    script = _APT_RESOLVE.format(
        host=SNAPSHOT_HOST,
        root=SNAPSHOT_ROOT,
        suites=" ".join(SNAPSHOT_SUITES),
        component=SNAPSHOT_COMPONENT,
        packages=" ".join(UBUNTU_FIXTURES),
    )
    command = [
        "docker", "run", "--rm", "--platform", _DOCKER_PLATFORM[architecture],
        platform_image(architecture), "bash", "-c", script,
    ]  # fmt: skip
    try:
        completed = subprocess.run(  # noqa: S603 - the harness's own pinned image
            command, capture_output=True, text=True, timeout=900, check=False
        )
    except FileNotFoundError as error:
        raise MirrorError("Generating the Ubuntu fixture needs Docker.") from error
    except subprocess.TimeoutExpired as error:
        raise MirrorError("Resolving the Ubuntu fixture timed out.") from error
    if completed.returncode != 0:
        raise MirrorError(f"Resolving the Ubuntu fixture failed: {completed.stderr.strip()[-400:]}")
    urls = [
        line.split("'", 2)[1]
        for line in completed.stdout.splitlines()
        if line.startswith("'") and line.count("'") >= 2
    ]
    if not urls:
        raise MirrorError("The Ubuntu fixture resolved no package files.")
    return urls


def _pebble_entries(architecture: str, store: _StoreFn) -> None:
    version = f"v{PEBBLE_VERSION}"
    store(
        PEBBLE_RELEASE_HOST,
        _PEBBLE_ASSET.format(version=version, arch=_DEB_ARCH[architecture]),
        architecture,
    )
    for source in _PEBBLE_CERTS:
        store(PEBBLE_RAW_HOST, f"letsencrypt/pebble/{version}/{source}", architecture)


def _wordpress_entries(architecture: str, store: _StoreFn) -> None:
    store(WORDPRESS_HOST, WORDPRESS_ARCHIVE, architecture)
    store(
        WORDPRESS_API_HOST,
        WORDPRESS_CHECKSUMS,
        architecture,
        source=WORDPRESS_CHECKSUMS_SOURCE,
    )


def _composer_entries(architecture: str, store: _StoreFn) -> None:
    """Every distribution archive the fixture application's lock pins."""
    if not COMPOSER_LOCK.exists():
        return
    document = _object(json.loads(COMPOSER_LOCK.read_text(encoding="utf-8")), "the lock")
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise MirrorError("The fixture composer lock lists no packages.")
    for value in packages:
        dist = _object(value, "a fixture package").get("dist")
        if not isinstance(dist, dict):
            continue
        url = dist.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            continue
        host, _, path = url.partition("://")[2].partition("/")
        store(host, path, architecture)


def pebble_files(architecture: str) -> tuple[Path, Path, Path, Path]:
    """Pebble's binary, its HTTPS certificate and key, and the ACME root, from the mirror.

    docs/quality.md#native-layer. The lane runs the binary with the certificate it serves
    HTTPS from; the root is what Caddy trusts through ``acme_ca_root`` for the ACME
    transport.
    """
    root = cache_root()
    deb_arch = _DEB_ARCH[architecture]
    version = f"v{PEBBLE_VERSION}"
    asset = _PEBBLE_ASSET.format(version=version, arch=deb_arch)
    archive = root / PEBBLE_RELEASE_HOST / asset
    if not archive.exists():
        raise MirrorError(f"The mirror is missing {archive.name}. Run mirror.sh -- fetch.")
    directory = root / f"pebble-{deb_arch}"
    binary = directory / "pebble"
    if not binary.exists():
        directory.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as tar:
            member = next(
                (
                    item
                    for item in tar.getmembers()
                    if item.isfile() and item.name.endswith("/pebble")
                ),
                None,
            )
            extracted = tar.extractfile(member) if member is not None else None
            if extracted is None:
                raise MirrorError(f"{archive.name} carries no Pebble binary.")
            binary.write_bytes(extracted.read())
            binary.chmod(0o755)
    certificates = root / PEBBLE_RAW_HOST / f"letsencrypt/pebble/v{PEBBLE_VERSION}/test/certs"
    named = (
        certificates / "pebble.minica.pem",
        certificates / "localhost" / "cert.pem",
        certificates / "localhost" / "key.pem",
    )
    for path in named:
        if not path.exists():
            raise MirrorError(f"The mirror is missing {path.name}. Run mirror.sh -- fetch.")
    return binary, named[1], named[2], named[0]


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
    parser.add_argument(
        "--host-architecture",
        action="store_true",
        help="generate this host's architecture only, keeping the other entries",
    )
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    root = cache_root()
    if options.command == "generate":
        manifest = generate(root, (host_architecture(),) if options.host_architecture else None)
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
