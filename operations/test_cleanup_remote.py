"""The engine's checked-in cleanup body against real systemd on a disposable server.

Tagged ``ssh`` and skipped unless the native suite's disposable Ubuntu server is
configured. The test proves that the reviewed targets arrive through stdin staging, the
systemd unit collects itself, and the postcondition reads actual systemd state.
"""

import uuid
from typing import override

from django.contrib.auth.models import Permission
from django.test import tag

from bootstrap.apply_remote_testing import ApplyAcceptanceTestCase
from discovery.fakes import run_worker
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Result, Verification


@tag("ssh")
class CleanupAcceptanceTests(ApplyAcceptanceTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in ("view_changes", "change_site", "change_shared"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))

    def make_retained_unit(self, command: str) -> str:
        unit = f"barectl-apply-{uuid.uuid4().hex}.service"
        self.administer(
            f"/usr/bin/systemd-run --quiet --unit={unit} --service-type=exec "
            f"--remain-after-exit {command}"
        )
        self.wait_terminal(unit)
        return unit

    def test_reviewed_cleanup_stages_body_on_stdin_and_clears_native_units(self) -> None:
        exited = self.make_retained_unit("/usr/bin/true")
        failed = self.make_retained_unit("/usr/bin/false")

        self.client.post(f"/servers/{self.server.pk}/changes/prepare/", {"kind": "cleanup_runs"})
        run_worker()
        preparation = ChangePreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, "succeeded", preparation.failure)
        review = ChangeReview.objects.get(preparation=preparation)
        targets = [str(item["unit"]) for item in review.document["targets"]]
        self.assertEqual(targets, sorted([exited, failed]))

        self.client.post(f"/changes/{preparation.pk}/apply/", {"affected_sites": "on"})
        run = ChangeRun.objects.get(review=review)
        run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, "succeeded", run.failure)
        self.assertEqual(run.execution, Result.SUCCEEDED)
        self.assertEqual(run.verification, Verification.PASSED)
        self.assertEqual(self.units(), [])
        self.assertIn('barectl-result {"class":"succeeded"}', self.journal(run.unit_name))
        suffix = run.unit_name.removeprefix("barectl-apply-").removesuffix(".service")
        body_path = f"/run/lock/barectl/body-{suffix}.sh"
        self.assertEqual(self.administer(f"test ! -e {body_path}; echo $?"), "0\n")
