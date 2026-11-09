"""Build, cache and load the L0 snapshot image: a plain Ubuntu 26.04 server.

docs/quality.md#native-layer. L0 is the pinned base image by digest (``pins.json``) with
the server packages and the harness's fixture CA, so a scenario starts from the same
foundation on every host. The image is keyed by a hash of its inputs, so a change to the
base, the Dockerfile or the CA builds a new image and every host agrees on its name.

``V040`` is the one prepared layer that is not built from this release: a preparation
scenario boots L0, runs the ``v0.4.0`` tag's own controller against it, and commits the
result. Its key names the exact tag commit, so a different tag or a changed preparation
flow never reuses the image, and ``ensure("V040")`` raises instead of falling back to a
current layer.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path

from . import mirror
from .docker import DockerError, docker

REPOSITORY = Path(__file__).resolve().parent.parent
FIXTURE = REPOSITORY / "docker" / "disposable-server"
DOCKERFILE = FIXTURE / "Dockerfile"
FIXTURE_DOCKERFILE = FIXTURE / "fixture.Dockerfile"
PINS = FIXTURE / "pins.json"
IMAGE = "barectl-disposable-l0"
RELEASE = "26.04"
# Raise when an L0 layer's native behavior or contents change.
L0_FORMAT = "2"
# Raise when a prepared layer's contents change beyond the bodies its key names. GitHub cache
# keys are immutable, so this also retires an archive saved under a key whose tag it no
# longer holds.
PREPARED_FORMAT = "2"
# The 1.0 compatibility fixture is the v0.4.0 tag's own product managing a real L0 server,
# never a current snapshot relabelled (docs/v1.0-qualification.md).
V040_TAG = "v0.4.0"
V040_COMMIT = "e6edf430cea3d7df3e990fb00ae6c6b1eefa2464"
# Raise when the v0.4.0 preparation flow or the fixture's contents change.
V040_FORMAT = "1"


def base(release: str = RELEASE) -> str:
    """The pinned Ubuntu base image, by digest, from ``pins.json``."""
    pins = json.loads(PINS.read_text(encoding="utf-8"))
    value = pins.get(f"ubuntu-{release}")
    if not isinstance(value, str) or "@sha256:" not in value:
        raise ValueError(f"pins.json has no digest for ubuntu-{release}.")
    return value


def _layer(layer: str) -> tuple[str, str, str]:  # noqa: C901 - one closed layer table
    if layer == "L0":
        return RELEASE, "l0", "l0"
    if layer == "L1":
        return RELEASE, "l1", "l1"
    if layer == "L2":
        return RELEASE, "l2", "l2"
    if layer == "L3":
        return RELEASE, "l3", "l3"
    if layer == "L4":
        return RELEASE, "l4", "l4"
    if layer == "L5":
        return RELEASE, "l5", "l5"
    if layer == "V040":
        return RELEASE, "v040", "v040"
    if layer == "L0-standing":
        return RELEASE, "l0-standing", "standing-26.04"
    if layer == "fixture":
        return RELEASE, "fixture", "fixture"
    if layer == "L0-24.04":
        return "24.04", "l0", "l0-24.04"
    raise ValueError(f"Unknown native image layer {layer!r}.")


def key(layer: str = "L0") -> str:
    release, _, _ = _layer(layer)
    digest = hashlib.sha256(f"{L0_FORMAT} {layer} {release} {base(release)}".encode())
    digest.update((FIXTURE_DOCKERFILE if layer == "fixture" else DOCKERFILE).read_bytes())
    if layer == "L1":
        digest.update(foundation_inputs())
    if layer == "L2":
        digest.update(prepared_sites_inputs())
    if layer == "L3":
        digest.update(prepared_wordpress_inputs())
    if layer == "L4":
        digest.update(prepared_cache_inputs())
    if layer == "L5":
        digest.update(prepared_laravel_cache_inputs())
    if layer == "V040":
        # The tag commit, the L0 it was applied to and the preparation format decide the
        # fixture; a different v0.4.0 commit or a changed flow rebuilds it.
        digest.update(f"{V040_TAG} {V040_COMMIT} {V040_FORMAT} {key('L0')}".encode())
    certificate, _ = mirror.fixture_ca()
    digest.update(certificate.read_bytes())
    return digest.hexdigest()[:12]


def _django() -> None:
    """Configure Django for a snapshot key that hashes a change body (CLI and tests alike)."""
    from django.apps import apps

    if not apps.ready:
        import django

        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
        django.setup()


def prepared_sites_inputs(l1_key: str | None = None) -> bytes:
    """The prepared-sites layer follows the product's Create site body and the L1 key."""
    _django()
    from sites import change

    digest = hashlib.sha256((key("L1") if l1_key is None else l1_key).encode())
    digest.update(change.BODY_BYTES)
    return digest.digest()


def prepared_wordpress_inputs(l1_key: str | None = None) -> bytes:
    """The WordPress layer follows L1 and the database and WordPress bodies it applies."""
    _django()
    from databases import engine as database_engine
    from wordpress import convention as wordpress_convention
    from wordpress import create

    digest = hashlib.sha256((key("L1") if l1_key is None else l1_key).encode())
    digest.update(database_engine.BODY_BYTES)
    digest.update(create.BODY_BYTES)
    digest.update(
        f"{wordpress_convention.CORE_VERSION} {wordpress_convention.CORE_ARCHIVE_SIZE}".encode()
    )
    digest.update(f"prepared-wordpress-{PREPARED_FORMAT}".encode())
    return digest.digest()


def prepared_cache_inputs(l3_key: str | None = None) -> bytes:
    """The prepared-cache layer follows L3 and the two installs it carries."""
    _django()
    from cache import engine as cache_engine
    from sites import client_change

    digest = hashlib.sha256((key("L3") if l3_key is None else l3_key).encode())
    digest.update(cache_engine.BODY_BYTES)
    digest.update(client_change.BODY_BYTES)
    # The layer also carries a second site, so a per-site cache can be proved isolated.
    digest.update(f"l4-other-site-{PREPARED_FORMAT}".encode())
    return digest.digest()


def prepared_laravel_cache_inputs(l1_key: str | None = None) -> bytes:
    """The prepared-Laravel cache layer follows L1 and the bodies its setup applies."""
    _django()
    from automation import worker_change
    from cache import engine as cache_engine
    from laravel import change as laravel_change
    from laravel import create as laravel_create
    from sites import client_change

    digest = hashlib.sha256((key("L1") if l1_key is None else l1_key).encode())
    for body in (
        laravel_create.BODY_BYTES,
        laravel_change.BODY_BYTES,
        worker_change.BODY_BYTES,
        cache_engine.BODY_BYTES,
        client_change.BODY_BYTES,
    ):
        digest.update(body)
    # The fixture files the preparation pushes live in the scenario; the prepared format
    # retires a key when they or the layer's contents change.
    digest.update(f"l5-laravel-cache-{PREPARED_FORMAT}".encode())
    return digest.digest()


def canonical_foundation_payload() -> bytes:
    """Render the real engine with fixed identity/clock placeholders for snapshot keys."""
    from django.apps import apps

    if not apps.ready:
        import django

        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
        django.setup()
    from bootstrap import foundation
    from operations import engine
    from operations.models import ChangeReview
    from runtimes.catalog import Architecture, load

    machine = docker("info", "--format", "{{.Architecture}}").strip()
    architecture = Architecture(mirror.lock_architecture(machine))
    catalog = load()
    installer = catalog.installer(architecture)
    context = engine.BodyContext(
        "barectl-apply-" + "0" * 32 + ".service",
        "00000000-0000-0000-0000-000000000000",
        90000,
    )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": foundation.BODY_SHA256,
        "architecture": str(architecture),
        "precondition_digest": "0" * 64,
        "installer_url": installer.url,
        "installer_sha256": installer.sha256,
        "nix_mode": "install",
        "caddy_mode": "install",
        "profiles": {
            b.entry: b.path for b in catalog.offered(architecture) if b.entry in foundation.PROFILES
        },
    }
    review = ChangeReview(document=document, sites_read="", sites_digest="")
    body = foundation.body(document, context)
    rendered = engine.payload(
        foundation.HOST_FOUNDATION, review, context, body, engine.body_path(context.unit)
    )
    return rendered.encode() + b"\0" + body.source


def foundation_inputs(payload: bytes | None = None) -> bytes:
    """L1 follows canonical rendered payload bytes, catalog lock and pinned base."""
    if payload is None:
        payload = canonical_foundation_payload()
    digest = hashlib.sha256(payload)
    digest.update((REPOSITORY / "runtimes" / "catalog_lock.json").read_bytes())
    digest.update(base().encode())
    from runtimes import change, observation
    from runtimes.configuration import render

    digest.update(change.BODY_BYTES)
    digest.update(observation.READ_SOURCE.encode())
    for entry in ("php84", "php85"):
        files = render(entry)
        digest.update((files.ini + files.master + files.pool + files.unit + files.probe).encode())
    return digest.digest()


def tag(layer: str = "L0") -> str:
    release, _, _ = _layer(layer)
    return f"{IMAGE}:{release}-{key(layer)}"


def cache_key(layer: str = "L0") -> str:
    _, _, archive_name = _layer(layer)
    return f"{archive_name}-{key(layer)}"


def exists(image: str) -> bool:
    try:
        docker("image", "inspect", "-f", "{{.Id}}", image)
    except DockerError:
        return False
    return True


def build(layer: str = "L0") -> str:
    release, target, _ = _layer(layer)
    image = tag(layer)
    certificate, _ = mirror.fixture_ca()
    fixtures = FIXTURE / "fixtures"
    source = FIXTURE_DOCKERFILE if layer == "fixture" else DOCKERFILE
    with tempfile.TemporaryDirectory(prefix="barectl-l0-") as context:
        shutil.copy(source, Path(context) / "Dockerfile")
        shutil.copy(certificate, Path(context) / "fixture-ca.crt")
        if fixtures.exists():
            shutil.copytree(fixtures, Path(context) / "fixtures")
        docker(
            "build", "-q", "--target", target,
            "--build-arg", f"RELEASE={release}", "--build-arg", f"BASE={base(release)}",
            "-t", image, "--label", f"barectl.built={int(time.time())}", context,
            timeout=1800,
        )  # fmt: skip
    return image


def _archive(layer: str) -> Path | None:
    directory = os.environ.get("BARECTL_NATIVE_L0_CACHE")
    if not directory:
        return None
    _, _, archive_name = _layer(layer)
    return Path(directory) / f"{archive_name}.tar"


def load(layer: str) -> bool:
    """Whether this host has the keyed image, loading it from the cache archive if needed."""
    image = tag(layer)
    if exists(image):
        return True
    archive = _archive(layer)
    if archive is None or not archive.exists():
        return False
    docker("load", "--input", str(archive), timeout=600)
    if exists(image):
        return True
    print(  # noqa: T201 - the preparation stage reports why it rebuilds
        f"{archive.name} does not hold {image}; the layer will be prepared again.",
        file=sys.stderr,
    )
    return False


def store(layer: str, *, replace: bool = False) -> None:
    """Write the keyed image to the cache archive, if one is configured and missing.

    ``replace`` lets a preparation stage overwrite an archive left by an older cache key;
    without it the file's name alone would keep stale bytes in place.
    """
    image = tag(layer)
    archive = _archive(layer)
    if archive is None or not exists(image):
        return
    if archive.exists():
        if not replace:
            return
        archive.unlink()
    archive.parent.mkdir(parents=True, exist_ok=True)
    descriptor, partial = tempfile.mkstemp(dir=archive.parent, suffix=".partial")
    os.close(descriptor)
    try:
        docker("save", "--output", partial, image, timeout=600)
        os.replace(partial, archive)
    finally:
        Path(partial).unlink(missing_ok=True)


def archive_matches(layer: str = "L0") -> bool:
    """Whether the saved archive names this host's keyed image, not an older one."""
    archive = _archive(layer)
    if archive is None or not archive.exists():
        return False
    import tarfile

    try:
        with tarfile.open(archive) as saved:
            member = saved.extractfile("manifest.json")
            if member is None:
                return False
            manifest = json.loads(member.read())
    except OSError, ValueError, tarfile.TarError:
        return False
    if not isinstance(manifest, list):
        return False
    return any(
        isinstance(entry, dict) and tag(layer) in entry.get("RepoTags", []) for entry in manifest
    )


def archived(layer: str = "L0") -> bool:
    """Whether the keyed archive exists, without loading it into Docker."""
    archive = _archive(layer)
    return archive is not None and archive.exists()


def ensure(layer: str = "L0") -> str:
    """The keyed image for this host, loading it from the cache archive or building it."""
    image = tag(layer)
    if load(layer):
        return image
    if layer == "L1":
        raise DockerError(
            "The foundation L1 snapshot is missing. Run the S1 HostFoundation scenario first."
        )
    if layer == "L2":
        raise DockerError(
            "The prepared-sites L2 snapshot is missing. Run its preparation scenario first."
        )
    if layer == "L3":
        raise DockerError(
            "The prepared-WordPress L3 snapshot is missing. Run its preparation scenario first."
        )
    if layer == "L4":
        raise DockerError(
            "The prepared-cache L4 snapshot is missing. Run its preparation scenario first."
        )
    if layer == "L5":
        raise DockerError(
            "The prepared-Laravel L5 snapshot is missing. Run its preparation scenario first."
        )
    if layer == "V040":
        raise DockerError(
            "The v0.4.0 compatibility V040 snapshot is missing. Run its preparation "
            "scenario first; a current snapshot is never a substitute."
        )
    build(layer)
    store(layer)
    return image


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="images", description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("cache-key", "build"))
    parser.add_argument(
        "--layer",
        default="L0",
        choices=(
            "L0",
            "L0-standing",
            "L0-24.04",
            "L1",
            "L2",
            "L3",
            "L4",
            "L5",
            "V040",
            "fixture",
        ),
    )
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if options.command == "cache-key":
        print(cache_key(options.layer))  # noqa: T201
        return 0
    print(build())  # noqa: T201
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
