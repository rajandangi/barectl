"""Readiness reviews and staging orders against the simulated site server (sites.fakes)."""

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
from operations.models import RemoteOperation
from servers.testing import HTMX_FRAGMENT

from .fakes import NAMES, TLS_PERMISSIONS, TlsServer, TlsTestCase
from .models import PlanTlsReadiness, PlanTlsStaging, ReadinessName, RunStaging, StagingRunResult

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
STAGED = (
    # Certbot 2.x issues SAN-only certificates: the subject line exists but is empty.
    "subject=\n"
    "notBefore=Sep 30 12:00:00 2026 GMT\n"
    "notAfter=Dec 29 12:00:00 2026 GMT\n"
    "X509v3 Subject Alternative Name: \n"
    "    DNS:shop.example.com, DNS:www.shop.example.com\n"
)


@override_settings(ACME_AUTHORITIES=[AUTHORITY])
class ReadinessTestCase(TlsTestCase):
    """A server with the site shop, its challenge route published and the DNS answering."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.add_site("shop", NAMES)
        self.site.add_challenge("shop")
        self.tls = TlsServer(self.site)
        for name in NAMES:
            self.tls.set_records(name, a=ADDRESSES)
        self.tls.answer(self.remote)

    def readiness(self, *, perms: tuple[str, ...] = TLS_PERMISSIONS) -> object:
        self.sign_in_with(*perms)
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/readiness/prepare/",
            {"readiness-identifier": "shop"},
        )
        self.run_worker()
        return response

    def latest_plan(self) -> ConfigurationPlan | None:
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        return ConfigurationPlan.objects.filter(preparation=preparation).first()


class StagingTestCase(ReadinessTestCase):
    """The same server with the guarded Certbot installed and no staging lineage yet."""

    staging_permissions: ClassVar[tuple[str, ...]] = (*TLS_PERMISSIONS, "apply_tlsplan")

    @override
    def setUp(self) -> None:
        super().setUp()
        self.tls.certbot_version = "2.9.0"
        self.systemd = NativeSystemd()
        self.systemd.answer(self.remote)

    def stage(self, **fields: str) -> object:
        self.sign_in_with(*self.staging_permissions)
        posted = {
            "identifier": "shop",
            "email": "ops@example.com",
            "authority": AUTHORITY["directory"],
            "terms": "on",
        }
        posted.update(fields)
        data = {f"staging-{name}": value for name, value in posted.items()}
        response = self.client.post(f"/servers/{self.server.pk}/tls/staging/prepare/", data)
        self.run_worker()
        return response


class ReadinessReviewTests(ReadinessTestCase):
    def test_the_review_records_each_name_and_the_authority(self) -> None:
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        readiness = PlanTlsReadiness.objects.get(plan=plan)
        self.assertEqual(readiness.identifier, "shop")
        self.assertEqual(readiness.authority, AUTHORITY["directory"])
        self.assertEqual(readiness.authority_name, "Pebble")
        self.assertEqual(readiness.webroot, "/var/lib/letsencrypt/shop")
        names = list(ReadinessName.objects.filter(plan=plan).order_by("position"))
        self.assertEqual([record.name for record in names], list(NAMES))
        self.assertEqual(names[0].a_list, ADDRESSES)
        self.assertEqual(names[0].problem, "")
        self.assertEqual(
            list(plan.evidence.filter(kind=Kind.EXTERNAL_READS).values_list("summary", flat=True)),
            [
                (
                    "shop.example.com, www.shop.example.com resolved from the server's own "
                    "resolver to this server's addresses; the directory answered over IPv4; "
                    "the clock is NTP synchronized. Read nothing but these answers."
                )
            ],
        )

    def test_the_review_is_rendered(self) -> None:
        self.readiness()
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "What the server's resolver answered")
        self.assertContains(page, "Prepare TLS readiness review")

    def test_a_name_behind_a_proxy_refuses(self) -> None:
        self.tls.set_records(NAMES[0], a=("198.51.100.7",))
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.DESTINATION, reasons)
        texts = " ".join(plan.refusals.values_list("text", flat=True))
        self.assertIn("A proxy or content delivery network serves the name", texts)

    def test_split_destinations_refuse_multiple_server_routing(self) -> None:
        self.tls.set_records(NAMES[0], a=("203.0.113.10",))
        self.tls.set_records(NAMES[1], a=("203.0.113.11",))
        self.tls.ipv4 = ("203.0.113.10", "203.0.113.11")
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.DESTINATION, reasons)
        texts = " ".join(plan.refusals.values_list("text", flat=True))
        self.assertIn("do not all resolve to the same addresses", texts)

    def test_an_aaaa_record_needs_a_global_ipv6_address(self) -> None:
        self.tls.ipv6 = ()
        for name in NAMES:
            self.tls.set_records(name, a=ADDRESSES, aaaa=("2001:db8::10",))
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.DESTINATION, reasons)

    def test_aaaa_records_add_the_ipv6_reachability_read(self) -> None:
        self.tls.ipv6 = ("2001:db8::10",)
        for name in NAMES:
            self.tls.set_records(name, a=ADDRESSES, aaaa=("2001:db8::10",))
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        summary = plan.evidence.get(kind=Kind.EXTERNAL_READS).summary
        self.assertIn("the directory answered over IPv4 and IPv6", summary)

    def test_an_unreachable_ipv6_directory_refuses(self) -> None:
        self.tls.ipv6 = ("2001:db8::10",)
        for name in NAMES:
            self.tls.set_records(name, a=ADDRESSES, aaaa=("2001:db8::10",))
        self.tls.directory = ""
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.INCOMPLETE, reasons)

    def test_caa_records_for_another_authority_refuse(self) -> None:
        for name in NAMES:
            self.tls.set_records(name, a=ADDRESSES, caa=("other-ca.example",))
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.AUTHORITY, reasons)

    def test_the_authoritys_own_caa_records_are_admitted(self) -> None:
        for name in NAMES:
            self.tls.set_records(name, a=ADDRESSES, caa=(AUTHORITY["caa"],))
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))

    def test_an_unsynchronized_clock_refuses(self) -> None:
        self.tls.ntp = False
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        text = plan.refusals.filter(reason=Reason.INCOMPLETE).first()
        assert text is not None  # noqa: S101 - the clock refusal is on the list
        self.assertIn("clock is not NTP synchronized", text.text)

    def test_an_unreachable_directory_refuses(self) -> None:
        self.tls.directory = ""
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.INCOMPLETE, reasons)

    def test_a_name_that_does_not_resolve_refuses(self) -> None:
        self.tls.dns.clear()
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.INCOMPLETE, reasons)

    def test_the_challenge_route_is_a_prerequisite(self) -> None:
        self.site.challenges.discard("shop")
        self.site.paths.pop("/var/lib/letsencrypt/shop", None)
        self.readiness()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.PREREQUISITE, reasons)

    def test_viewers_may_not_prepare(self) -> None:
        self.readiness(perms=("view_server", "view_tlsplan"))
        self.assertFalse(PlanPreparation.objects.exists())


class StagingReviewTests(StagingTestCase):
    def test_the_order_is_reviewed_with_the_readings(self) -> None:
        self.stage()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        staging = PlanTlsStaging.objects.get(plan=plan)
        self.assertEqual(staging.identifier, "shop")
        self.assertEqual(staging.email, "ops@example.com")
        self.assertEqual(staging.authority_name, "Pebble")
        self.assertEqual(staging.cert_name, "sshop")
        self.assertLess(staging.payload_bytes or 0, 16384)
        kinds = list(plan.effects.values_list("kind", flat=True))
        self.assertIn(Effect.STAGING_ORDER, kinds)
        self.assertIn(Kind.EXTERNAL_READS, list(plan.evidence.values_list("kind", flat=True)))

    def test_the_order_is_rendered(self) -> None:
        self.stage()
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Where the order's artifacts go, and nothing else")
        self.assertContains(page, "Prepare staging order plan")

    def test_certbot_absent_refuses(self) -> None:
        self.tls.certbot_version = None
        self.stage()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.PREREQUISITE, reasons)

    def test_certbot_at_another_version_refuses(self) -> None:
        self.tls.certbot_version = "3.3.3"
        self.stage()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.CUSTOMIZED, reasons)

    def test_an_existing_staging_lineage_is_a_plan_without_changes(self) -> None:
        self.tls.staged = STAGED
        self.stage()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertTrue(plan.no_changes)

    def test_a_staging_lineage_for_other_names_is_refused(self) -> None:
        self.tls.staged = STAGED.replace("DNS:www.shop.example.com", "DNS:other.example.com")
        self.stage()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        reasons = list(plan.refusals.values_list("reason", flat=True))
        self.assertIn(Reason.COLLISION, reasons)
        self.assertFalse(plan.no_changes)

    def test_the_payload_rechecks_the_parsed_digest(self) -> None:
        from . import staging_native

        payload = staging_native.payload(
            "barectl-apply-0123456789abcdef0123456789abcdef.service",
            "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23",
            90000,
            identifier="shop",
            php_version="8.3",
            webroot="/var/lib/letsencrypt/shop",
            names=("shop.example.com",),
            email="ops@example.com",
            directory=AUTHORITY["directory"],
            site_digest="abc",
        )
        # The digest command prints "<hash>  -"; the review stores the hash alone.
        self.assertIn('| cut -d" " -f1)" = abc', payload)
        self.assertLessEqual(len(payload.encode()), 16384 - 1024)

    def test_an_order_does_not_need_a_separate_terms_checkbox(self) -> None:
        self.sign_in_with(*self.staging_permissions)
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/staging/prepare/",
            {
                "staging-identifier": "shop",
                "staging-email": "ops@example.com",
                "staging-authority": AUTHORITY["directory"],
            },
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(PlanPreparation.objects.exists())
        self.assertNotContains(response, "I accept the authority")

    def test_an_unlisted_authority_is_refused_by_the_form(self) -> None:
        self.stage(authority="https://unknown.test/dir")
        self.assertFalse(PlanPreparation.objects.exists())


class StagingApplyTests(StagingTestCase):
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

    def apply_plan(self) -> ApplyRun:
        self.stage()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.systemd.on_submit = lambda: setattr(self.tls, "staged", STAGED)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run

    def test_an_applied_order_succeeds_and_records_the_certificate(self) -> None:
        run = self.apply_plan()
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        result = StagingRunResult.objects.get(run=run)
        self.assertEqual(result.not_after, "Dec 29 12:00:00 2026 GMT")
        self.assertEqual(result.problems, "")
        self.assertEqual(RunStaging.objects.get(run=run).cert_name, "sshop")
        audit = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(audit, "Staged a certificate for shop.example.com")
        self.assertContains(audit, "Dec 29 12:00:00 2026 GMT")

    def test_each_order_boundary_is_named(self) -> None:
        from . import staging_apply

        run = self.apply_plan()
        for status, expected in (
            (95, "DNS or routing problem"),
            (96, "CAA records"),
            (97, "rate-limited the order"),
            (98, "refused the staging account"),
            (99, "another reason"),
        ):
            self.assertIn(expected.split()[0], staging_apply.failure(run, Execution.FAILED, status))

    def test_a_missing_staged_certificate_fails_verification(self) -> None:
        self.systemd.on_submit = lambda: None
        self.stage()
        plan = self.latest_plan()
        assert plan is not None  # noqa: S101 - queued on an idle server
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.verification, Verification.UNAVAILABLE)
