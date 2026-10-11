"""The cleanup kind: its review, its body and its verification through the engine.

Real views, services, the lifecycle, the worker, persistence and rendering run against the
simulated systemd of ``operations.fakes``. ``docker/disposable-server`` keeps the legacy
native coverage of the adapter until the new harness replaces it.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import skipUnless

from django.test import SimpleTestCase

from operations.models import Consent

from . import cleanup, engine, native
from .fakes import BOOT_ID, UPTIME_CENTISECONDS, ChangeTestCase, finished_unit
from .models import ChangeReview, Result, Verification

EXITED = "barectl-apply-" + "a" * 32 + ".service"
FAILED = "barectl-apply-" + "b" * 32 + ".service"
RUNNING = "barectl-apply-" + "c" * 32 + ".service"
SHELL = Path(__file__).parent / "bodies" / "clear_runs.sh"


class CleanupReviewTests(ChangeTestCase):
    def test_finished_and_running_units_partition_into_a_shared_review(self) -> None:
        from .fakes import EngineUnit

        self.systemd.units[EXITED] = finished_unit(1)
        self.systemd.units[FAILED] = finished_unit(2, failed=True)
        self.systemd.units[RUNNING] = EngineUnit(running=1)
        review = self.change()
        self.assertTrue(review.eligible)
        self.assertFalse(review.no_changes)
        self.assertEqual(review.consent, Consent.SHARED)
        self.assertEqual(review.affected_sites, [])
        self.assertEqual(
            [(target["unit"], target["invocation"]) for target in review.document["targets"]],
            [(EXITED, f"{1:032x}"), (FAILED, f"{2:032x}")],
        )
        self.assertIn("1 still running", " ".join(review.document["kept"]))
        # The review keeps its evidence fingerprint and its stages for the pages.
        self.assertIn("retained_units", review.document)
        self.assertTrue(review.document["stages"])
        self.assertEqual(review.boot_id, BOOT_ID)
        self.assertEqual(review.uptime_centiseconds, UPTIME_CENTISECONDS)
        self.assertEqual(
            review.admission_deadline_centiseconds,
            UPTIME_CENTISECONDS + 15 * 60 * 100,
        )

    def test_nothing_finished_is_a_read_review_without_changes(self) -> None:
        review = self.change()
        self.assertTrue(review.eligible)
        self.assertTrue(review.no_changes)
        self.assertEqual(review.consent, Consent.READ)
        self.assertEqual(review.effects, [])

    def test_unreadable_units_refuse_the_review(self) -> None:
        self.systemd.retained_fail = True
        preparation = self.prepare()
        self.assertEqual(preparation.status, "succeeded")
        review = ChangeReview.objects.get(preparation=preparation)
        self.assertFalse(review.eligible)
        self.assertIn("could not read", " ".join(review.document["refusals"]).lower())


class CleanupApplyTests(ChangeTestCase):
    def test_a_body_that_cannot_be_staged_is_not_submitted(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.systemd.stage_fail = True
        run = self.apply(review)
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.execution, Result.NOT_SUBMITTED)
        self.assertIn("could not read the server's state", run.failure)
        self.assertFalse(self.systemd.submissions)

    def test_a_reviewed_cleanup_clears_only_finished_units(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        self.systemd.units[FAILED] = finished_unit(2, failed=True)
        review = self.change()
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertContains(page, "Finished barectl runs to clear")
        self.assertContains(page, EXITED)
        self.assertContains(page, "Shared")
        self.assertContains(page, "Consent needed to apply")
        self.assertContains(page, "Stages")
        run = self.apply(review)
        self.assertEqual(run.status, "succeeded", run.failure)
        self.assertEqual(run.execution, Result.SUCCEEDED)
        self.assertEqual(run.verification, Verification.PASSED)
        # The payload carries only their identifiers; its body is sent separately on stdin.
        (submission,) = self.systemd.submissions
        self.assertIn(f"{EXITED}|{1:032x}|active|exited|success|1|0|0", submission)
        self.assertIn(f"{FAILED}|{2:032x}|failed|failed|exit-code|1|1|0", submission)
        self.assertIn("--collect", submission)
        self.assertNotIn("--remain-after-exit", submission)
        self.assertEqual(self.systemd.staged_digests, [cleanup.BODY_SHA256])
        self.assertFalse(self.systemd.staged_bodies)
        self.assertIn(engine.body_path(run.unit_name), submission)
        self.assertNotIn(cleanup.BODY_BYTES.decode(), submission)
        # The page shows the review, consent, stages and outcome.
        run_page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(run_page, "Applied and verified")
        self.assertContains(run_page, "Shared")
        self.assertContains(run_page, "Take the mutation lock")

    def test_a_refused_cleanup_stops_before_clearing_anything(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.systemd.result_class = "refused"
        self.systemd.reason = "evidence"
        run = self.apply(review)
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.execution, Result.REFUSED)
        self.assertEqual(run.result_reason, "evidence")
        self.assertIn("stopped before changing anything", run.failure)
        self.assertIn(EXITED, self.systemd.units)

    def test_a_partial_cleanup_is_reported_as_partly_applied(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        review = self.change()
        self.systemd.result_class = "partial"
        self.systemd.reason = "cleanup"
        run = self.apply(review)
        self.assertEqual(run.execution, Result.PARTIAL)
        self.assertIn("partly applied", run.failure)
        self.assertIn(EXITED, self.systemd.units)


class CleanupBodyTests(SimpleTestCase):
    def test_the_body_is_the_checked_in_script_and_its_parameters(self) -> None:
        document = {
            "version": 1,
            "targets": [
                {
                    "unit": EXITED,
                    "invocation": "a" * 32,
                    "active_state": "active",
                    "sub_state": "exited",
                    "result": "success",
                    "exec_main_code": 1,
                    "exec_main_status": 0,
                    "populated": 0,
                },
                {
                    "unit": FAILED,
                    "invocation": "b" * 32,
                    "active_state": "failed",
                    "sub_state": "failed",
                    "result": "exit-code",
                    "exec_main_code": 1,
                    "exec_main_status": 1,
                    "populated": 0,
                },
            ],
        }
        body = cleanup.body(document, engine.BodyContext(native.new_unit_name(), BOOT_ID, 590025))
        self.assertEqual(body.source, cleanup.BODY_BYTES)
        self.assertEqual(
            body.arguments,
            (
                (
                    f"{EXITED}|{'a' * 32}|active|exited|success|1|0|0 "
                    f"{FAILED}|{'b' * 32}|failed|failed|exit-code|1|1|0"
                ),
            ),
        )

    def test_targets_are_validated(self) -> None:
        document = {"version": 1, "targets": [{"unit": "nginx.service", "invocation": "a" * 32}]}
        context = engine.BodyContext(native.new_unit_name(), BOOT_ID, 1)
        for bad in (
            {},
            {"version": 1, "targets": []},
            document,
            {
                "version": 1,
                "targets": [
                    {
                        "unit": context.unit,
                        "invocation": "a" * 32,
                        "active_state": "active",
                        "sub_state": "exited",
                        "result": "success",
                        "exec_main_code": 1,
                        "exec_main_status": 0,
                        "populated": 0,
                    }
                ],
            },
        ):
            with self.subTest(document=bad), self.assertRaises(ValueError):
                cleanup.body(bad, context)

    def test_changed_unit_invocation_refuses_before_any_unit_is_cleared(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "clear_runs.sh"
            script.write_text(cleanup.BODY, encoding="utf-8")
            systemctl = root / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$*" >> "$SYSTEMCTL_LOG"\n'
                'case "$4" in\n'
                '  LoadState) printf "loaded\\n" ;;\n'
                '  InvocationID) printf "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\\n" ;;\n'
                "  *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            systemctl.chmod(0o700)
            command_log = root / "systemctl.log"
            target = f"{EXITED}|{'a' * 32}|active|exited|success|1|0|0"
            result = subprocess.run(  # noqa: S603 - fixed shell and checked-in test commands
                ["/bin/sh", str(script), target],
                capture_output=True,
                check=False,
                env={
                    **os.environ,
                    "PATH": f"{root}:/usr/bin:/bin",
                    "SYSTEMCTL_LOG": str(command_log),
                },
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn(
                'barectl-result {"class":"refused","reason":"evidence"}',
                result.stdout,
            )
            self.assertNotIn("systemctl stop", command_log.read_text())
            self.assertFalse(script.exists())

    @skipUnless(shutil.which("shellcheck"), "shellcheck is not installed")
    def test_the_checked_in_body_passes_shellcheck(self) -> None:
        command: list[str] = ["shellcheck", str(SHELL)]
        result = subprocess.run(  # noqa: S603 - the checked-in payload's own lint
            command,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
