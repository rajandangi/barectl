"""Build, cache and load the L0 snapshot image: a plain Ubuntu 26.04 server.

docs/quality.md#native-layer. L0 is the pinned base image by digest (``pins.json``) with
the server packages and the harness's fixture CA, so a scenario starts from the same
foundation on every host. The image is keyed by a hash of its inputs, so a change to the
base, the Dockerfile or the CA builds a new image and every host agrees on its name.
"""

import hashlib
import json
import os
import shutil
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


def base(release: str = RELEASE) -> str:
    """The pinned Ubuntu base image, by digest, from ``pins.json``."""
    pins = json.loads(PINS.read_text(encoding="utf-8"))
    value = pins.get(f"ubuntu-{release}")
    if not isinstance(value, str) or "@sha256:" not in value:
        raise ValueError(f"pins.json has no digest for ubuntu-{release}.")
    return value


def _layer(layer: str) -> tuple[str, str, str]:
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
    digest.update(b"l4-other-site-v1")
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
    return exists(image)


def store(layer: str) -> None:
    """Write the keyed image to the cache archive, if one is configured and missing."""
    image = tag(layer)
    archive = _archive(layer)
    if archive is None or archive.exists() or not exists(image):
        return
    archive.parent.mkdir(parents=True, exist_ok=True)
    descriptor, partial = tempfile.mkstemp(dir=archive.parent, suffix=".partial")
    os.close(descriptor)
    try:
        docker("save", "--output", partial, image, timeout=600)
        os.replace(partial, archive)
    finally:
        Path(partial).unlink(missing_ok=True)


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
    build(layer)
    store(layer)
    return image


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="images", description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("cache-key", "build"))
    parser.add_argument("--layer", default="L0", choices=("L0", "L1", "L2", "L3", "L4", "fixture"))
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if options.command == "cache-key":
        print(cache_key(options.layer))  # noqa: T201
        return 0
    print(build())  # noqa: T201
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
