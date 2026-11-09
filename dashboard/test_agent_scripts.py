"""The agent-facing scripts name the real failure without a full log download."""

import os
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase


class CheckLogTests(SimpleTestCase):
    def test_a_native_item_timeout_is_named(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binaries = Path(directory) / "bin"
            binaries.mkdir()
            gh = binaries / "gh"
            gh.write_text(
                "#!/bin/sh\n"
                'case "$*" in\n'
                '  *"--json jobs"*) exit 1 ;;\n'
                '  *"--log"*)\n'
                "    cat <<'EOF'\n"
                "2026-11-09T07:41:09.1562927Z [native] FAIL   0 tests  180.0s "
                "disposable.test_security_firewall.FirewallLifecycle — over 3 minutes\n"
                "2026-11-09T07:41:57.7754687Z ##[error]Process completed with exit code 1.\n"
                "EOF\n"
                "    exit 0 ;;\n"
                "esac\n"
                "exit 1\n",
                encoding="utf-8",
            )
            gh.chmod(0o755)
            result = subprocess.run(  # noqa: S603 - this repository's own script
                [str(Path(settings.BASE_DIR) / "scripts/check-log.sh"), "1"],
                env=os.environ | {"PATH": f"{binaries}:{os.environ['PATH']}"},
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[native] FAIL", result.stdout)
        self.assertIn("disposable.test_security_firewall.FirewallLifecycle", result.stdout)
        self.assertIn("over 3 minutes", result.stdout)
