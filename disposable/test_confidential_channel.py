"""S16: the confidential input channel on a real server.

docs/adr/0032-keep-secrets-in-private-native-files.md. The fast layer proves the commands;
this proves the native effect: the root-only tmpfs value is consumed by the transient unit
and gone on every exit path, and the canary never reaches the journal.
"""

import shlex
import time

from django.test import tag

from operations import engine, native
from operations.inputs import EMPTY_INPUTS
from operations.models import ChangeReview
from operations.secret_testing import SECRET_PROBE

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

CANARY = "barectl-native-canary-9c2f4a7e1d"
LOCK = native.LOCK_DIRECTORY


@tag(SCENARIO_TAG)
class ConfidentialChannelLifecycle(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s16conf"

    def stage_and_submit(self, secret: str, *, before_submit: str = "") -> str:
        """Stage the body and the value, submit the reviewed run, return its result class."""
        kind = SECRET_PROBE
        with self.shell() as shell:
            draft = kind.review(kind.inspect(shell, EMPTY_INPUTS), EMPTY_INPUTS)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertFalse(draft.no_changes)
            if draft.uptime_centiseconds is None:
                self.fail("No native clock.")
            unit = native.new_unit_name()
            secret_file = engine.secret_path(unit)
            context = engine.BodyContext(
                unit, draft.boot_id, draft.uptime_centiseconds + 90000, secret_path=secret_file
            )
            stored = ChangeReview(document=draft.document, sites_read="", sites_digest="")
            body = kind.body(draft.document, context)
            path = engine.body_path(unit)
            digest = str(draft.document["body_sha256"])
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, digest)), stdin=body.source
                ).exit_status,
                0,
            )
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_secret_command(secret_file, len(secret.encode()))),
                    stdin=secret.encode(),
                ).exit_status,
                0,
            )
            if before_submit:
                self.native(before_submit)
            payload = engine.payload(kind, stored, context, body, path, secret=secret_file)
            self.assertEqual(
                shell.run(shlex.join(native.submission(unit, payload, collect=True))).exit_status,
                0,
            )
            end = time.monotonic() + 30
            result = engine.read_result(shell, unit)
            while result is None and time.monotonic() < end:
                time.sleep(0.05)
                result = engine.read_result(shell, unit)
            if result is None:
                self.fail("No native outcome: " + self.native(f"journalctl -u {unit} -n 30"))
            # The value is gone and never reached the journal.
            self.assertNotIn(CANARY, self.native(f"journalctl -u {unit} -n 200"))
            self.assertEqual(self.native(f"test -e {secret_file}; echo $?").strip(), "1")
            self.assertEqual(self.native(f"test -e {path}; echo $?").strip(), "1")
            return result.result_class

    def test_a_value_is_consumed_and_removed_on_success(self) -> None:
        self.assertEqual(self.stage_and_submit(CANARY), "succeeded")

    def test_a_value_is_removed_when_the_payload_refuses(self) -> None:
        self.native(f"install -d -m 0700 {LOCK}")
        self.addCleanup(self.native, f"chmod 0700 {LOCK}")
        # An unsafe shared lock directory refuses admission before the body runs; the
        # payload's own trap must still remove the staged value.
        self.assertEqual(
            self.stage_and_submit(CANARY, before_submit=f"chmod 0755 {LOCK}"),
            "refused",
        )
