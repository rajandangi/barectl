"""HTTPS activations against the simulated site server (sites.fakes)."""

from typing import ClassVar, override

from django.contrib.auth.models import Permission
from django.test import override_settings

from bootstrap.fakes import NativeSystemd
from bootstrap.models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from operations.models import RemoteOperation
from sites.convention import Stage

from .fakes import NAMES, TLS_PERMISSIONS, TlsServer, TlsTestCase
from .models import ActivationRunResult, PlanTlsActivation, RunTlsActivation

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
AUTHORITY = {
    "directory": "https://pebble.test/dir",
    "caa": "pebble.test",
    "name": "Pebble",
}
ADDRESSES = ("203.0.113.10",)
# Certbot 2.x issues SAN-only certificates: the subject line exists but is empty.
ISSUED = (
    "subject=\n"
    "notBefore=Sep 30 12:00:00 2026 GMT\n"
    "notAfter=Dec 29 12:00:00 2026 GMT\n"
    "X509v3 Subject Alternative Name: \n"
    "    DNS:shop.example.com, DNS:www.shop.example.com\n"
    "serial=0A1B2C\n"
    "sha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
    "pubkey_cert=" + "1" * 64 + "\n"
    "pubkey_key=" + "1" * 64 + "\n"
    "curve=prime256v1\n"
    "renewal=yes\n"
)


@override_settings(ACME_AUTHORITIES=[AUTHORITY], ACME_PRODUCTION_DIRECTORY=AUTHORITY["directory"])
class ActivationTestCase(TlsTestCase):
    """The server with the site shop, its challenge route, the guarded Certbot and an
    issued production lineage."""

    activation_permissions: ClassVar[tuple[str, ...]] = (*TLS_PERMISSIONS, "apply_tlsplan")

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.add_site("shop", NAMES)
        self.site.add_challenge("shop")
        self.tls = TlsServer(self.site)
        for name in NAMES:
            self.tls.set_records(name, a=ADDRESSES)
        self.tls.certbot_version = "2.9.0"
        self.tls.production = ISSUED
        self.systemd = NativeSystemd()
        self.systemd.answer(self.remote)
        self.tls.answer(self.remote)

    def activate(self) -> object:
        self.sign_in_with(*self.activation_permissions)
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/activation/prepare/",
            {"activation-identifier": "shop"},
        )
        self.run_worker()
        return response

    def latest_plan(self) -> ConfigurationPlan | None:
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        return ConfigurationPlan.objects.filter(preparation=preparation).first()

    def apply_plan(self, *, stage: Stage = Stage.REDIRECT) -> ApplyRun:
        self.activate()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server

        def activate() -> None:
            self.site.add_activated("shop", stage)
            self.tls.default_reject = True

        self.systemd.on_submit = activate
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run


class ActivationReviewTests(ActivationTestCase):
    def test_the_review_records_the_candidates(self) -> None:
        self.activate()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        activation = PlanTlsActivation.objects.get(plan=plan)
        self.assertEqual(activation.names, "\n".join(NAMES))
        self.assertFalse(activation.redirect_only)
        self.assertTrue(activation.creates_default)
        self.assertEqual(activation.fingerprint, "ab" * 32)
        self.assertIsNotNone(activation.payload_bytes)
        kinds = set(plan.effects.values_list("kind", flat=True))
        self.assertEqual(
            kinds, {Effect.TLS_DEFAULT_SERVER, Effect.HTTPS_ACTIVATION, Effect.HTTP_REDIRECT}
        )

    def test_the_review_is_rendered(self) -> None:
        self.activate()
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Prepare HTTPS activation plan")
        self.assertContains(page, "/etc/letsencrypt/live/shop")
        self.assertContains(page, "https://shop.example.com")

    def test_a_missing_lineage_refuses(self) -> None:
        self.tls.production = ""
        self.activate()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.PREREQUISITE, reasons)
        self.assertFalse(PlanTlsActivation.objects.filter(plan=plan).exists())

    def test_a_lineage_for_other_names_refuses(self) -> None:
        self.tls.production = ISSUED.replace("DNS:www.shop.example.com", "DNS:other.example.com")
        self.activate()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.COLLISION, reasons)

    def test_a_competing_default_refuses(self) -> None:
        self.tls.competing_defaults = 1
        self.activate()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.CONFLICT, reasons)
        texts = " ".join(plan.refusals.values_list("text", flat=True))
        self.assertIn("default server on port 443", texts)

    def test_a_custom_default_refuses(self) -> None:
        self.tls.default_reject = True
        self.activate()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertFalse(PlanTlsActivation.objects.get(plan=plan).creates_default)

    def test_a_site_already_redirecting_is_a_plan_without_changes(self) -> None:
        self.site.add_activated("shop", Stage.REDIRECT)
        self.activate()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertTrue(plan.no_changes)
        activation = PlanTlsActivation.objects.get(plan=plan)
        self.assertEqual(activation.fingerprint, "ab" * 32)
        self.assertEqual(activation.not_after, "Dec 29 12:00:00 2026 GMT")

    def test_a_site_already_serving_https_proposes_only_the_redirect(self) -> None:
        self.site.add_activated("shop", Stage.HTTPS)
        self.activate()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        activation = PlanTlsActivation.objects.get(plan=plan)
        self.assertTrue(activation.redirect_only)
        self.assertEqual(activation.https_content, activation.preimage)


class ActivationApplyTests(ActivationTestCase):
    @override
    def assert_read_only(self) -> None:
        submissions = [
            c.split("--unit=", 1)[1].split()[0]
            for c in self.remote.commands
            if c.startswith(
                ("/usr/bin/systemd-run --unit=", "sudo -n /usr/bin/systemd-run --unit=")
            )
        ]
        self.assertEqual(len(submissions), len(set(submissions)), "A run was submitted twice")

    def test_an_applied_activation_succeeds_and_records_the_served_certificate(self) -> None:
        run = self.apply_plan()
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        result = ActivationRunResult.objects.get(run=run)
        self.assertEqual(result.problems, "")
        self.assertEqual(result.served.splitlines()[0], f"{NAMES[0]} {'ab' * 32}")
        self.assertTrue(result.rejects_unknown)
        self.assertTrue(result.host_checked)
        self.assertEqual(result.redirect, "HTTP 301 to https://shop.example.com")
        activation = RunTlsActivation.objects.get(run=run)
        self.assertIn("/var/backups/nginx/shop.conf.", activation.backup_path)
        audit = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(audit, "Activated HTTPS for shop.example.com")

    def test_an_unknown_name_still_served_fails_verification(self) -> None:
        self.tls.unknown_served = True
        run = self.apply_plan()
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn("unknown name still received a certificate", run.failure)

    def test_a_host_mismatch_served_fails_verification(self) -> None:
        self.tls.host_served = True
        run = self.apply_plan()
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn("Host different from valid SNI", run.failure)

    def test_a_missing_redirect_fails_verification(self) -> None:
        self.tls.redirect_status = "200"
        run = self.apply_plan()
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn("301 redirect", run.failure)

    def test_each_boundary_is_named(self) -> None:
        from . import activation_apply, activation_native

        run = self.apply_plan()
        for status, expected in (
            (activation_native.Exit.DEFAULT, "rejection server"),
            (activation_native.Exit.RESTORED, "restored from the preimage"),
            (activation_native.Exit.NOT_SERVING, "served for a reviewed name"),
            (activation_native.Exit.REDIRECT, "verified HTTPS state is in place"),
            (activation_native.Exit.NOT_REDIRECTING, "does not redirect"),
        ):
            self.assertIn(expected, activation_apply.failure(run, Execution.PARTIAL, status))

    def test_applying_needs_the_apply_permission(self) -> None:
        self.activate()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.user.user_permissions.remove(Permission.objects.get(codename="apply_tlsplan"))
        response = self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ApplyRun.objects.filter(plan_number=plan.pk).exists())
