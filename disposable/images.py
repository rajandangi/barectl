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
    if layer == "L0-standing":
        return RELEASE, "l0-standing", "standing-26.04"
    if layer == "L0-24.04":
        return "24.04", "l0", "l0-24.04"
    raise ValueError(f"Unknown native image layer {layer!r}.")


def key(layer: str = "L0") -> str:
    release, _, _ = _layer(layer)
    digest = hashlib.sha256(f"{L0_FORMAT} {layer} {release} {base(release)}".encode())
    digest.update(DOCKERFILE.read_bytes())
    if layer == "L1":
        digest.update(foundation_inputs())
    certificate, _ = mirror.fixture_ca()
    digest.update(certificate.read_bytes())
    return digest.hexdigest()[:12]


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
    architecture = Architecture.AARCH64 if machine in {"aarch64", "arm64"} else Architecture.X86_64
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
    return digest.digest()


def tag(layer: str = "L0") -> str:
    release, _, _ = _layer(layer)
    return f"{IMAGE}:{release}-{key(layer)}"


def cache_key() -> str:
    return f"l0-{key()}"


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
    with tempfile.TemporaryDirectory(prefix="barectl-l0-") as context:
        shutil.copy(DOCKERFILE, Path(context) / "Dockerfile")
        shutil.copy(certificate, Path(context) / "fixture-ca.crt")
        docker(
            "build", "-q", "--target", target,
            "--build-arg", f"RELEASE={release}", "--build-arg", f"BASE={base(release)}",
            "-t", image, "--label", f"barectl.built={int(time.time())}", context,
            timeout=1800,
        )  # fmt: skip
    return image


def ensure(layer: str = "L0") -> str:
    """The L0 image for this host, loading it from the cache archive or building it."""
    _, _, archive_name = _layer(layer)
    image = tag(layer)
    if exists(image):
        return image
    archive_directory = os.environ.get("BARECTL_NATIVE_L0_CACHE")
    archive = Path(archive_directory) / f"{archive_name}.tar" if archive_directory else None
    if archive is not None and archive.exists():
        docker("load", "--input", str(archive), timeout=600)
        if exists(image):
            return image
    if layer == "L1":
        raise DockerError(
            "The foundation L1 snapshot is missing. Run the S1 HostFoundation scenario first."
        )
    build(layer)
    if archive is not None:
        archive.parent.mkdir(parents=True, exist_ok=True)
        docker("save", "--output", str(archive), image, timeout=600)
    return image


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="images", description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("cache-key", "build"))
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if options.command == "cache-key":
        print(cache_key())  # noqa: T201
        return 0
    print(build())  # noqa: T201
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
