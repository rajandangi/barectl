"""Fast validator: a fixture job's canary never survives a journal read (Phase C #397).

The real systemd journal feeds the product's own bounded reader as root. The canary is read
from the site's private environment by a fixture unit, so it reaches the journal exactly as a
failing job's output would; the server-side scrub must replace it before any page exists.
"""

import json
from typing import override

from django.test import tag

from automation.convention import queue_role, service_name
from logs import read as log_read
from logs.bodies import read

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

IDENTIFIER = "v397logs"
CANARY = "canary-journal-native-5e2b"
UNIT = service_name(IDENTIFIER, queue_role(1))
PRIVATE = f"/var/www/{IDENTIFIER}/private"
SCRIPT = f"{PRIVATE}/fixture.sh"
UNIT_TEXT = (
    "[Unit]\n"
    "Description=Barectl verification fixture job\n"
    "\n"
    "[Service]\n"
    "Type=oneshot\n"
    f"ExecStart={SCRIPT}\n"
)
SCRIPT_TEXT = (
    f"#!/bin/sh\n. {PRIVATE}/laravel.env\nprintf 'fixture job printed %s\\n' \"$APP_KEY\"\n"
)


@tag(SCENARIO_TAG)
class JournalLogValidators(ScenarioTestCase):
    layer = "L1"
    prefix = "v397logs"
    validator = True

    @override
    def setUp(self) -> None:
        super().setUp()
        # Cleanups run last-registered first: stop the unit, then remove its file and tree.
        self.addCleanup(self.native, f"rm -rf /var/www/{IDENTIFIER} /etc/valkey/{IDENTIFIER}.conf")
        self.addCleanup(self.native, f"rm -f /etc/systemd/system/{UNIT}")
        self.addCleanup(self.native, "systemctl daemon-reload")
        self.addCleanup(self.native, f"systemctl disable --now {UNIT} 2>/dev/null || true")

    def install_fixture(self) -> None:
        self.native(
            f"install -d -m 0700 {PRIVATE} && "
            f"printf 'APP_KEY=base64:{CANARY}\\nAPP_ENV=production\\n' > {PRIVATE}/laravel.env && "
            f"chmod 0600 {PRIVATE}/laravel.env"
        )
        with self.shell() as shell:
            for path, text, mode in (
                (SCRIPT, SCRIPT_TEXT, "0755"),
                (f"/etc/systemd/system/{UNIT}", UNIT_TEXT, "0644"),
            ):
                written = shell.run(f"install -D -m {mode} /dev/stdin {path}", stdin=text.encode())
                self.assertEqual(written.exit_status, 0, written.stdout)
        self.native("systemctl daemon-reload")
        self.native(f"systemctl start {UNIT}")

    def test_a_fixture_jobs_canary_never_reaches_a_page(self) -> None:
        self.install_fixture()
        with self.shell() as shell:
            page = log_read.read(shell, IDENTIFIER, "queue_workers")
            self.assertEqual(page.state, "observed", page.note)
            self.assertTrue(page.lines)
            rendered = json.dumps(page.document())
            self.assertIn(read.REDACTED, rendered)
            self.assertIn("fixture job printed", rendered)
            self.assertNotIn(CANARY, rendered)
            self.assertTrue(page.newest)
            # A source with no unit is not configured, never an empty read.
            self.assertEqual(
                log_read.read(shell, IDENTIFIER, "object_cache").state, "not_configured"
            )
            # A live read starts after the newest cursor and sees only what followed it.
            self.native(f"systemctl start {UNIT}")
            live = log_read.read(shell, IDENTIFIER, "queue_workers", cursor=page.newest)
            self.assertTrue(live.live)
            self.assertTrue(live.lines)
            self.assertNotIn(CANARY, json.dumps(live.document()))
            self.assertLessEqual(len(live.lines), read.MAX_LINES)


__all__ = ["JournalLogValidators"]
