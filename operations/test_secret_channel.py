"""The confidential input channel end to end, driven by the minimal secret-writing kind.

A canary value must reach the server only through ADR 0032's channel and appear nowhere a
record or a page could leak it (docs/adr/0032-keep-secrets-in-private-native-files.md).
"""

import hashlib
from datetime import timedelta
from typing import TYPE_CHECKING, override

from django.contrib.auth.models import Permission
from django.test import Client
from django.utils import timezone

from operations import confidential, engine
from operations.fakes import APPLY_PERMISSIONS, PREPARE_PERMISSIONS, ChangeTestCase
from operations.models import (
    MANAGE_SECRETS,
    ChangePreparation,
    ChangeReview,
    ChangeRun,
)
from operations.secret_testing import SECRET_PROBE, SLUG

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse
# A value no run may ever store, print or send outside the confidential channel.
CANARY = "barectl-canary-1f4c2e7a9d5b3a08"
# ``sign_in_with`` and ``grant`` take permission codenames, not ``app.codename``.
MANAGE = MANAGE_SECRETS.rsplit(".", 1)[1]


class SecretChannelTests(ChangeTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        confidential.reset()
        self.addCleanup(confidential.reset)
        engine.register_kind(SECRET_PROBE)
        self.addCleanup(engine._KINDS.pop, SLUG, None)

    def prepared(self) -> ChangeReview:
        """Prepare the probe kind as an operator with manage-secrets; return its review."""
        self.sign_in_with("view_server", *PREPARE_PERMISSIONS, MANAGE)
        self.client.post(f"/servers/{self.server.pk}/changes/prepare/", {"kind": SLUG})
        self.run_worker()
        preparation = ChangePreparation.objects.latest("queued_at", "pk")
        review = ChangeReview.objects.filter(preparation=preparation).first()
        if review is None:
            self.fail(f"The preparation {preparation.pk} recorded no review.")
        return review

    def apply_secret(
        self, review: ChangeReview, secret: str | None = CANARY, *, follow: bool = False
    ) -> _MonkeyPatchedWSGIResponse:
        self.sign_in_with(*APPLY_PERMISSIONS, MANAGE)
        data: dict[str, str] = {"affected_sites": "on"}
        if secret is not None:
            data["secret"] = secret
        return self.client.post(f"/changes/{review.preparation_id}/apply/", data, follow=follow)

    def run_of(self, review: ChangeReview) -> ChangeRun:
        run = ChangeRun.objects.filter(review=review).first()
        if run is None:
            self.fail("No run was queued.")
        return run

    def assert_canary_absent(self, *pages: object) -> None:
        """The canary appears in no command, unit, journal, row, event or response."""
        sources = [
            "\n".join(self.remote.commands),
            "\n".join(self.systemd.submissions),
            "\n".join(self.systemd.journals),
            "\n".join(self.systemd.systemctl_outputs),
            "\n".join(getattr(page, "content", b"").decode() for page in pages),
        ]
        for model in (ChangeReview, ChangeRun):
            sources.extend(
                " ".join(str(getattr(row, field.name)) for field in model._meta.fields)
                for row in model.objects.all()
            )
        for source in sources:
            self.assertNotIn(CANARY, source)

    def test_a_value_reaches_the_body_sealed_and_leaves_no_trace(self) -> None:
        review = self.prepared()
        response = self.apply_secret(review, follow=True)
        run = self.run_of(review)
        # Stored encrypted, never in plaintext, and bound to a deadline.
        self.assertNotEqual(run.secret_sealed, "")
        self.assertNotIn(CANARY, run.secret_sealed)
        self.assertIsNotNone(run.secret_expires_at)
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, "succeeded", run.failure)
        # The value arrived only as standard input and the payload removed it on exit.
        self.assertIn(hashlib.sha256(CANARY.encode()).hexdigest(), self.systemd.secret_digests)
        self.assertEqual(self.systemd.secret_removals, [engine.secret_path(run.unit_name)])
        # Cleared once sent.
        self.assertEqual(run.secret_sealed, "")
        self.assertIsNone(run.secret_expires_at)
        self.assert_canary_absent(
            response,
            self.client.get(f"/changes/{run.review.preparation_id}/"),
            self.client.get(f"/runs/{run.pk}/"),
        )

    def test_a_value_is_unreadable_after_a_worker_restart(self) -> None:
        review = self.prepared()
        self.apply_secret(review)
        # A new worker process mints a new sealing key.
        confidential.rotate()
        self.run_worker()
        run = self.run_of(review)
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertIn("no longer readable", run.failure)
        self.assertEqual(run.secret_sealed, "")
        self.assertEqual(self.systemd.secret_digests, [])

    def test_a_value_expires_after_ten_minutes(self) -> None:
        review = self.prepared()
        self.apply_secret(review)
        run = self.run_of(review)
        ChangeRun.objects.filter(pk=run.pk).update(
            secret_expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertIn("10-minute", run.failure)
        self.assertEqual(self.systemd.secret_digests, [])

    def test_a_missing_value_is_refused_before_a_run(self) -> None:
        review = self.prepared()
        response = self.apply_secret(review, secret=None, follow=True)
        self.assertFalse(ChangeRun.objects.filter(review=review).exists())
        self.assertContains(response, "Type the confidential value")

    def test_a_staged_value_is_removed_on_every_exit_path(self) -> None:
        outcomes = (
            ("succeeded", False, "succeeded"),
            ("refused", False, "refused"),
            ("failed", False, "failed"),
            ("timed_out", False, "timed_out"),
            # systemd refuses the submission: no unit runs, so the worker removes both files.
            ("succeeded", True, "not_submitted"),
        )
        for result_class, reject, expected in outcomes:
            with self.subTest(result_class=result_class, reject=reject):
                self.systemd.result_class = result_class
                self.systemd.reject = reject
                self.systemd.secret_removals = []
                review = self.prepared()
                self.apply_secret(review)
                run = self.run_of(review)
                self.run_worker()
                run.refresh_from_db()
                self.assertEqual(run.execution, expected, run.failure)
                self.assertEqual(self.systemd.secret_removals, [engine.secret_path(run.unit_name)])
                self.assertEqual(self.systemd.staged_secrets, {})

    def test_a_known_value_is_scrubbed_from_the_run_audit(self) -> None:
        review = self.prepared()
        self.apply_secret(review)
        run = self.run_of(review)
        ChangeRun.objects.filter(pk=run.pk).update(
            failure=f"leaked {CANARY}", progress_stage=f"stage {CANARY}"
        )
        engine._scrub_run(run.pk, (CANARY,))
        run.refresh_from_db()
        self.assertNotIn(CANARY, run.failure)
        self.assertNotIn(CANARY, run.progress_stage)

    def test_a_secret_submission_needs_a_csrf_token(self) -> None:
        review = self.prepared()
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(
            f"/changes/{review.preparation_id}/apply/",
            {"affected_sites": "on", "secret": CANARY},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.filter(review=review).exists())

    def test_preparing_a_secret_change_needs_manage_secrets(self) -> None:
        self.sign_in_with("view_server", *PREPARE_PERMISSIONS)
        response = self.client.post(f"/servers/{self.server.pk}/changes/prepare/", {"kind": SLUG})
        self.assertEqual(response.status_code, 403)

    def test_applying_a_secret_change_needs_manage_secrets(self) -> None:
        review = self.prepared()
        self.user.user_permissions.remove(Permission.objects.get(codename=MANAGE))
        self.sign_in_with(*APPLY_PERMISSIONS)
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/",
            {"affected_sites": "on", "secret": CANARY},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.filter(review=review).exists())

    def test_a_revoked_account_fails_before_dispatch(self) -> None:
        review = self.prepared()
        self.apply_secret(review)
        self.user.user_permissions.remove(Permission.objects.get(codename=MANAGE))
        self.run_worker()
        run = self.run_of(review)
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertIn("no longer allowed", run.failure)
        self.assertEqual(self.systemd.secret_digests, [])
