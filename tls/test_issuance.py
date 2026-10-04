"""Production orders against the simulated site server (sites.fakes)."""

from typing import ClassVar, override

from django.test import override_settings

from bootstrap.fakes import NativeSystemd
from bootstrap.models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from discovery.ssh import CommandResult
from operations.models import RemoteOperation

from .fakes import NAMES, TLS_PERMISSIONS, TlsServer, TlsTestCase
from .models import IssuanceRunResult, PlanTlsIssuance, RunTlsIssuance

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason
Kind = PlanEvidence.Kind
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
class IssuanceTestCase(TlsTestCase):
    """The server with the site shop, its challenge route, the guarded Certbot and the
    production authority, and no production lineage yet."""

    issuance_permissions: ClassVar[tuple[str, ...]] = (*TLS_PERMISSIONS, "issue_certificate")

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.add_site("shop", NAMES)
        self.site.add_challenge("shop")
        self.tls = TlsServer(self.site)
        for name in NAMES:
            self.tls.set_records(name, a=ADDRESSES)
        self.tls.certbot_version = "2.9.0"
        self.systemd = NativeSystemd()
        self.systemd.answer(self.remote)
        self.tls.answer(self.remote)

    def issue(self, **fields: str) -> object:
        self.sign_in_with(*self.issuance_permissions)
        posted = {
            "identifier": "shop",
            "email": "ops@example.com",
            "terms": "on",
        }
        posted.update(fields)
        data = {f"issuance-{name}": value for name, value in posted.items()}
        response = self.client.post(f"/servers/{self.server.pk}/tls/issuance/prepare/", data)
        self.run_worker()
        return response

    def latest_plan(self) -> ConfigurationPlan | None:
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        return ConfigurationPlan.objects.filter(preparation=preparation).first()

    def apply_plan(self, *, production: str | None = None) -> ApplyRun:
        self.issue()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        issued = ISSUED if production is None else production
        self.systemd.on_submit = lambda: setattr(self.tls, "production", issued)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run


class IssuanceReviewTests(IssuanceTestCase):
    def test_the_review_records_the_order(self) -> None:
        self.issue()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        issuance = PlanTlsIssuance.objects.get(plan=plan)
        self.assertEqual(issuance.identifier, "shop")
        self.assertEqual(issuance.names, "\n".join(NAMES))
        self.assertEqual(issuance.authority, AUTHORITY["directory"])
        self.assertEqual(issuance.authority_name, "Pebble")
        self.assertEqual(issuance.webroot, "/var/lib/letsencrypt/shop")
        self.assertEqual(issuance.cert_name, "shop")
        self.assertEqual(issuance.account, "")
        self.assertIsNotNone(issuance.payload_bytes)
        self.assertTrue(plan.effects.filter(kind=Effect.PRODUCTION_ORDER).exists())
        self.assertTrue(plan.evidence.filter(kind=Kind.LINEAGE_REVALIDATION).exists())

    def test_the_review_is_rendered(self) -> None:
        self.issue()
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Prepare production order plan")
        self.assertContains(page, "/etc/letsencrypt/live/shop")

    def test_an_order_does_not_need_a_separate_terms_checkbox(self) -> None:
        self.sign_in_with(*self.issuance_permissions)
        self.client.post(
            f"/servers/{self.server.pk}/tls/issuance/prepare/",
            {"issuance-identifier": "shop", "issuance-email": "ops@example.com"},
        )
        self.run_worker()
        self.assertTrue(PlanPreparation.objects.filter(action="tls_issuance").exists())

    def test_an_existing_matching_lineage_is_a_plan_without_changes(self) -> None:
        self.tls.production = ISSUED
        self.issue()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertTrue(plan.no_changes)
        self.assertFalse(plan.effects.filter(kind=Effect.PRODUCTION_ORDER).exists())
        self.assertIsNone(PlanTlsIssuance.objects.get(plan=plan).payload_bytes)
        self.assertTrue(
            any(
                command.startswith("sudo -n ") and "regr.json" in command
                for command in self.remote.commands
            )
        )

    def test_denied_lineage_inspection_refuses_instead_of_ordering_again(self) -> None:
        self.tls.production = ISSUED
        self.remote.answers.insert(
            0,
            lambda command: (
                CommandResult(1, "")
                if command.startswith("sudo -n -l ") and "regr.json" in command
                else None
            ),
        )
        self.issue()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertFalse(plan.eligible)
        self.assertFalse(plan.effects.filter(kind=Effect.PRODUCTION_ORDER).exists())
        self.assertTrue(plan.refusals.filter(reason=Reason.PRIVILEGE).exists())

    def test_a_lineage_for_other_names_is_refused(self) -> None:
        self.tls.production = ISSUED.replace("DNS:www.shop.example.com", "DNS:other.example.com")
        self.issue()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.COLLISION, reasons)
        texts = " ".join(plan.refusals.values_list("text", flat=True))
        self.assertIn("never adopts or replaces a lineage", texts)

    def test_an_account_with_another_contact_is_refused(self) -> None:
        self.tls.accounts = ('{"body":{"contact":["mailto:other@example.com"]}}',)
        self.issue()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.COLLISION, reasons)
        texts = " ".join(plan.refusals.values_list("text", flat=True))
        self.assertIn("never silently reuses another account", texts)

    def test_a_matching_account_is_reused(self) -> None:
        self.tls.accounts = ('{"body":{"contact":["mailto:ops@example.com"]}}',)
        self.issue()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertEqual(PlanTlsIssuance.objects.get(plan=plan).account, "ops@example.com")

    def test_certbot_absent_refuses_before_the_order(self) -> None:
        self.tls.certbot_version = None
        self.issue()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.PREREQUISITE, reasons)


class IssuanceApplyTests(IssuanceTestCase):
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

    def test_an_applied_order_succeeds_and_records_the_certificate(self) -> None:
        run = self.apply_plan()
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        result = IssuanceRunResult.objects.get(run=run)
        self.assertEqual(result.not_after, "Dec 29 12:00:00 2026 GMT")
        self.assertEqual(result.names, "\n".join(NAMES))
        self.assertEqual(result.fingerprint, "ab" * 32)
        self.assertEqual(result.serial, "0A1B2C")
        self.assertEqual(result.key_curve, "ecdsa prime256v1")
        self.assertTrue(result.key_matches)
        self.assertTrue(result.renewal)
        self.assertEqual(result.problems, "")
        self.assertEqual(RunTlsIssuance.objects.get(run=run).cert_name, "shop")
        audit = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(audit, "Issued a production certificate for shop.example.com")
        self.assertContains(audit, "Dec 29 12:00:00 2026 GMT")

    def test_a_key_outside_the_policy_fails_verification(self) -> None:
        run = self.apply_plan(
            production=ISSUED.replace("curve=prime256v1", "curve=secp384r1").replace(
                "pubkey_key=" + "1" * 64, "pubkey_key=" + "2" * 64
            )
        )
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn("ECDSA P-256", run.failure)
        self.assertIn("does not match the lineage's private key", run.failure)

    def test_each_order_boundary_is_named(self) -> None:
        from . import issuance_apply

        run = self.apply_plan()
        for status, expected in (
            (95, "DNS or routing problem"),
            (96, "CAA records"),
            (97, "rate-limited the order"),
            (98, "refused the production account"),
            (99, "another reason"),
        ):
            self.assertIn(
                expected.split()[0], issuance_apply.failure(run, Execution.FAILED, status)
            )

    def test_applying_needs_the_issue_permission(self) -> None:
        from django.contrib.auth.models import Permission

        self.issue()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.user.user_permissions.remove(Permission.objects.get(codename="issue_certificate"))
        response = self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ApplyRun.objects.filter(plan_number=plan.pk).exists())

    def test_the_fragment_lists_the_order(self) -> None:
        self.issue()
        response = self.client.get(
            f"/servers/{self.server.pk}/tls/",
            headers={"HX-Request": "true", "HX-Request-Type": "partial"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Prepare production order plan")
