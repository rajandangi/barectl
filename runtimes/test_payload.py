import base64
import gzip
import subprocess
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from .change import BODY_BYTES


class RuntimeBodyCleanupTests(SimpleTestCase):
    def test_refusal_removes_its_staged_body_without_any_runtime_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory) / "body.sh"
            staged.write_bytes(BODY_BYTES)
            result = subprocess.run(  # noqa: S603 - this repository's fixed body, refusal before mutation
                [
                    "/bin/sh",
                    str(staged),
                    "php84",
                    "/unavailable",
                    "/unavailable",
                    "a" * 64,
                    base64.b64encode(
                        gzip.compress(
                            b"import json; print(json.dumps("
                            b'{"digest": "b" * 64, "admissible": True}))',
                            mtime=0,
                        )
                    ).decode(),
                    "",
                    "",
                    "",
                    "",
                    "",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('"class":"refused"', result.stdout)
            self.assertFalse(staged.exists())
