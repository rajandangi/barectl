"""The approved PHP source as its publisher serves it now; docs/quality.md#live-php-source-check.

Barectl's own index admission judges the publisher's current signed metadata for every
supported release and architecture, without a server.
"""

import hashlib
import shlex
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from .runner import setup_django


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - the approved HTTPS source
        body: bytes = response.read()
        return body


def main() -> int:
    setup_django()
    from bootstrap import php_supply, php_trust, releases

    with tempfile.TemporaryDirectory() as directory:
        key = Path(directory) / "apt.gpg"
        key.write_bytes(fetch(f"{php_supply.SOURCE_URL}apt.gpg"))
        if hashlib.sha256(key.read_bytes()).hexdigest() != php_supply.KEY_SHA256:
            print(  # noqa: T201
                "The published key no longer has the approved SHA-256; a changed key needs "
                "review under ADR 0016."
            )
            return 1
        failed = False
        for release in releases.RELEASES.values():
            index = Path(directory) / f"{release.codename}_InRelease"
            index.write_bytes(fetch(f"{php_supply.SOURCE_URL}dists/{release.codename}/InRelease"))
            command = php_trust.index_authentication(
                release, path=shlex.quote(str(index)), key=shlex.quote(str(key))
            )
            evidence = subprocess.run(  # noqa: S603 - Barectl's own index authentication
                ["/bin/sh", "-c", command], capture_output=True, text=True, check=False
            ).stdout
            for architecture in sorted(releases.ARCHITECTURES):
                refusal = php_trust.signature_refusal(evidence, release, architecture)
                failed = failed or refusal is not None
                print(  # noqa: T201
                    f"Ubuntu {release.version} ({release.codename}) {architecture}: "
                    f"{refusal or 'current'}"
                )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
