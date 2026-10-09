import hashlib
import io
import subprocess
import time
from email.utils import formatdate
from unittest.mock import patch

from django.test import SimpleTestCase

from bootstrap import php_supply, releases

from . import php_source_live

KEY = b"approved key"


class LivePhpSourceCheckTests(SimpleTestCase):
    def check(self, published: float, key: bytes = KEY) -> tuple[int, str]:
        def fetch(url: str) -> bytes:
            return key if url.endswith("apt.gpg") else url.encode()

        def authenticate(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            codename = next(r.codename for r in releases.RELEASES.values() if r.codename in argv[2])
            return subprocess.CompletedProcess(
                argv,
                0,
                f"CLOCK|{int(time.time())}\n"
                f"[GNUPG:] VALIDSIG {php_supply.PRIMARY_FINGERPRINT} x 1 0 4 0 1 10 01 "
                f"{php_supply.PRIMARY_FINGERPRINT}\n"
                f"Origin: deb.sury.org\nSuite: {codename}\nCodename: {codename}\n"
                f"Date: {formatdate(published, usegmt=True)}\n"
                "Architectures: amd64 arm64 armhf\nComponents: main\n",
            )

        output = io.StringIO()
        with (
            patch.object(php_source_live, "fetch", fetch),
            patch("disposable.php_source_live.subprocess.run", authenticate),
            patch.object(php_supply, "KEY_SHA256", hashlib.sha256(KEY).hexdigest()),
            patch("sys.stdout", output),
        ):
            return php_source_live.main(), output.getvalue()

    def test_current_publisher_metadata_passes_for_every_release_and_architecture(self) -> None:
        status, output = self.check(time.time() - 3600)
        self.assertEqual(status, 0, output)
        self.assertEqual(output.count(": current"), 2 * len(releases.RELEASES))

    def test_week_old_metadata_fails_with_barectl_refusal(self) -> None:
        status, output = self.check(time.time() - 8 * 86400)
        self.assertEqual(status, 1)
        self.assertIn("stopped being current", output)

    def test_unapproved_key_fails_before_reading_indexes(self) -> None:
        status, output = self.check(time.time() - 3600, key=b"rotated key")
        self.assertEqual(status, 1)
        self.assertIn("SHA-256", output)
        self.assertNotIn("current", output)
