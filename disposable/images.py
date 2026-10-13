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
# Raise when the l0 stage changes what the image holds.
L0_FORMAT = "1"


def base() -> str:
    """The pinned Ubuntu base image, by digest, from ``pins.json``."""
    pins = json.loads(PINS.read_text(encoding="utf-8"))
    value = pins.get(f"ubuntu-{RELEASE}")
    if not isinstance(value, str) or "@sha256:" not in value:
        raise ValueError(f"pins.json has no digest for ubuntu-{RELEASE}.")
    return value


def key() -> str:
    digest = hashlib.sha256(f"{L0_FORMAT} {RELEASE} {base()}".encode())
    digest.update(DOCKERFILE.read_bytes())
    certificate, _ = mirror.fixture_ca()
    digest.update(certificate.read_bytes())
    return digest.hexdigest()[:12]


def tag() -> str:
    return f"{IMAGE}:{RELEASE}-{key()}"


def cache_key() -> str:
    return f"l0-{key()}"


def exists(image: str) -> bool:
    try:
        docker("image", "inspect", "-f", "{{.Id}}", image)
    except DockerError:
        return False
    return True


def build() -> str:
    image = tag()
    certificate, _ = mirror.fixture_ca()
    with tempfile.TemporaryDirectory(prefix="barectl-l0-") as context:
        shutil.copy(DOCKERFILE, Path(context) / "Dockerfile")
        shutil.copy(certificate, Path(context) / "fixture-ca.crt")
        docker(
            "build", "-q", "--target", "l0",
            "--build-arg", f"BASE={base()}",
            "-t", image, "--label", f"barectl.built={int(time.time())}", context,
            timeout=1800,
        )  # fmt: skip
    return image


def ensure() -> str:
    """The L0 image for this host, loading it from the cache archive or building it."""
    image = tag()
    if exists(image):
        return image
    archive_directory = os.environ.get("BARECTL_NATIVE_L0_CACHE")
    archive = Path(archive_directory) / f"{RELEASE}.tar" if archive_directory else None
    if archive is not None and archive.exists():
        docker("load", "--input", str(archive), timeout=600)
        if exists(image):
            return image
    build()
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
