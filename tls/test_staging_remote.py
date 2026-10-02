"""Reviewed readiness and staging orders on a real, disposable server (docs/tls.md).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Through the dashboard request, the worker,
Barectl's SSH connection and actual resolvectl, systemd, Certbot and Nginx, with the local
Pebble ACME fixtures standing in for the staging authority. Ground truth is read with
``openssl``, ``journalctl`` and ``docker exec``. The administrator creates the site
``shop`` by the convention with its challenge route; a reviewed setup is applied first.
"""

import shlex
from typing import ClassVar, override
from unittest import skipUnless

from django.contrib.auth.models import Permission
from django.test import override_settings

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from discovery.fakes import run_worker
from disposable import acme
from operations.models import RemoteOperation
from sites.convention import Stage, render_placeholder, render_site
from sites.test_review_remote import PUT_BACK, SET_ASIDE, create_site, remove_site

from . import staging_native
from .models import PlanTlsReadiness, PlanTlsStaging, StagingRunResult
from .test_renewal_remote import LOCK
from .test_setup_remote import PURGE, SetupTestCase

Status = RemoteOperation.Status
NAMES = ("shop.test", "www.shop.test")
LIVE = "/etc/letsencrypt-staging/shop/live/sshop"


PEBBLE_AUTHORITY = {"directory": acme.DIRECTORY, "caa": "pebble", "name": "Pebble"}
PROXY_AUTHORITY = {
    "directory": acme.FAULT_DIRECTORY,
    "caa": "pebble",
    "name": "Pebble fault proxy",
}


@skipUnless(acme.CONFIGURED, "Set BARECTL_SSH_TEST_CONTAINER and BARECTL_ACME_TEST_*")
@override_settings(ACME_AUTHORITIES=[PEBBLE_AUTHORITY, PROXY_AUTHORITY])
class StagingTestCase(SetupTestCase):
    php: ClassVar[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        acme.install_trust_and_resolver(cls)

    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in ("view_tlsplan", "prepare_tlsplan", "apply_tlsplan"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        from discovery.releases import SUPPORTED

        type(self).php = SUPPORTED[release].php
        self.administer(PURGE)
        run = self.apply_setup(self.eligible())
        self.assertEqual(
            (run.status, run.verification), (Status.SUCCEEDED, Verification.PASSED), run.failure
        )
        ApplyRun.objects.all().delete()
        ConfigurationPlan.objects.all().delete()
        self.clear_units()
        self.addCleanup(self.administer, PUT_BACK)
        self.administer(SET_ASIDE)
        self.administer(create_site("shop", NAMES, self.php))
        self.administer(
            f"printf %s {shlex.quote(render_placeholder('shop'))} >/var/www/shop/public/index.html"
        )
        route = shlex.quote(render_site("shop", NAMES, ipv6=True, stage=Stage.CHALLENGE))
        self.administer(
            f"printf %s {route} >/etc/nginx/sites-available/shop.conf && nginx -t -q "
            "&& systemctl reload nginx"
        )
        # The webroot as an applied challenge route leaves it; the site admission
        # requires it, as the deploy tests' setup does.
        self.administer(
            "mkdir -p -m 0755 /var/lib/letsencrypt && mkdir -m 0750 /var/lib/letsencrypt/shop "
            "&& chown root:www-data /var/lib/letsencrypt/shop"
        )
        addresses = acme.server_addresses()
        for name in NAMES:
            acme.add_a(self, name, [addresses.ipv4])
            acme.add_aaaa(self, name, [addresses.ipv6])
        self.addCleanup(
            self.administer,
            f"{remove_site('shop', self.php)}; rm -rf /etc/letsencrypt-staging/shop "
            "/var/lib/letsencrypt-staging/shop /var/log/letsencrypt-staging/shop; true",
        )

    def readiness_plan(self) -> ConfigurationPlan:
        self.client.post(
            f"/servers/{self.server.pk}/tls/readiness/prepare/",
            {"readiness-identifier": "shop"},
        )
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def staging_plan(self, *, authority: str = acme.DIRECTORY) -> ConfigurationPlan:
        self.client.post(
            f"/servers/{self.server.pk}/tls/staging/prepare/",
            {
                "staging-identifier": "shop",
                "staging-email": "ops@example.com",
                "staging-authority": authority,
                "staging-terms": "on",
            },
        )
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def eligible_staging(self, *, authority: str = acme.DIRECTORY) -> ConfigurationPlan:
        plan = self.staging_plan(authority=authority)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def apply_staging(self, plan: ConfigurationPlan) -> ApplyRun:
        run = self.request(plan)
        run_worker()
        run.refresh_from_db()
        return run

    def staged(self) -> str:
        return self.administer(f"openssl x509 -noout -subject -dates -in {LIVE}/cert.pem")


class StagingReadinessTests(StagingTestCase):
    def test_readiness_reports_the_site_and_the_authority(self) -> None:
        plan = self.readiness_plan()
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        readiness = PlanTlsReadiness.objects.get(plan=plan)
        self.assertEqual(readiness.identifier, "shop")
        self.assertEqual(readiness.authority, acme.DIRECTORY)
        self.assertEqual(sorted(readiness.name_list), sorted(NAMES))

    def test_proxy_addresses_refuse_the_destination(self) -> None:
        acme.add_a(self, NAMES[0], ["192.0.2.1"])
        plan = self.readiness_plan()
        self.assertIn(
            "destination",
            list(plan.refusals.values_list("reason", flat=True)),
        )

    def test_a_shadow_caa_record_refuses_the_authority(self) -> None:
        acme.add_caa(self, NAMES[0], [("issue", "other.example")])
        plan = self.readiness_plan()
        self.assertIn("authority", list(plan.refusals.values_list("reason", flat=True)))

    def test_an_unresolved_name_refuses(self) -> None:
        acme.set_nxdomain(self, NAMES[0])
        plan = self.readiness_plan()
        self.assertIn(
            "incomplete",
            list(plan.refusals.values_list("reason", flat=True)),
            list(plan.readiness_names.values_list("name", "a", "aaaa", "problem")),
        )


class StagingJourneyTests(StagingTestCase):
    def test_a_site_orders_its_staging_certificate(self) -> None:
        plan = self.eligible_staging()
        staging = PlanTlsStaging.objects.get(plan=plan)
        self.assertEqual(staging.identifier, "shop")
        run = self.apply_staging(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        names = self.administer(f"openssl x509 -noout -ext subjectAltName -in {LIVE}/cert.pem")
        for name in NAMES:
            self.assertIn(f"DNS:{name}", names)
        result = StagingRunResult.objects.get(run=run)
        self.assertEqual(result.problems, "")
        self.assertNotEqual(result.not_after, "")
        # Production Certbot state holds no lineage for the site.
        self.assertEqual(self.administer("ls /etc/letsencrypt/live 2>/dev/null; true").strip(), "")
        # The placeholder still serves over HTTP.
        self.assertIn("Site shop is ready.", self.served_http())
        # A repeated review is a plan without changes.
        again = self.staging_plan()
        self.assertTrue(again.eligible, list(again.refusals.values_list("text", flat=True)))
        self.assertTrue(again.no_changes)

    def served_http(self) -> str:
        """The placeholder's status and body through the server's own HTTP client."""
        from . import native as status

        client = status.status_client(self.php)
        return self.administer(f"{client}; s 127.0.0.1 shop.test /; true")


class StagingFaultTests(StagingTestCase):
    def assert_order_failed(
        self, run: ApplyRun, status: int, text: str, *, lineage: bool = False
    ) -> None:
        self.assertEqual(
            (run.status, run.execution, run.exit_status, run.verification),
            (Status.FAILED, Execution.FAILED, status, Verification.NOT_APPLICABLE),
            run.failure,
        )
        self.assertIn(text, run.failure)
        self.assertEqual(self.staged_exists(), lineage)

    def staged_exists(self) -> bool:
        return (
            self.administer(f"test -f {LIVE}/cert.pem && echo yes || echo no; true").strip()
            == "yes"
        )

    def test_a_wrong_address_fails_the_challenge(self) -> None:
        plan = self.eligible_staging()
        # challtestsrv accumulates addresses, and the setup published the site's own AAAA,
        # so the name must hold only the wrong address to fail the challenge.
        acme.challtestsrv(self, "clear-a", {"host": acme.fqdn(NAMES[0])}, "clear-a")
        acme.challtestsrv(self, "clear-aaaa", {"host": acme.fqdn(NAMES[0])}, "clear-aaaa")
        acme.add_a(self, NAMES[0], ["192.0.2.1"])
        run = self.apply_staging(plan)
        self.assert_order_failed(run, staging_native.DNS, "DNS or routing")

    def test_caa_denial_fails_the_order(self) -> None:
        acme.inject_fault(self, "finalize", "caa")
        run = self.apply_staging(self.eligible_staging(authority=acme.FAULT_DIRECTORY))
        self.assert_order_failed(run, staging_native.AUTHORITY_CAA, "CAA")

    def test_a_rate_limit_reports_and_never_retries(self) -> None:
        acme.inject_fault(self, "newOrder", "rateLimited", retry_after="60")
        before = ApplyRun.objects.count()
        run = self.apply_staging(self.eligible_staging(authority=acme.FAULT_DIRECTORY))
        self.assert_order_failed(run, staging_native.RATE_LIMITED, "rate-limited")
        self.assertEqual(ApplyRun.objects.count(), before + 1)

    def test_a_refused_account_names_itself(self) -> None:
        acme.inject_fault(self, "newAccount", "unauthorized")
        run = self.apply_staging(self.eligible_staging(authority=acme.FAULT_DIRECTORY))
        self.assert_order_failed(run, staging_native.ACCOUNT, "account")

    def test_a_readiness_refusal_needs_no_order(self) -> None:
        acme.add_caa(self, NAMES[0], [("issue", "other.example")])
        plan = self.staging_plan()
        self.assertIn("authority", list(plan.refusals.values_list("reason", flat=True)))

    def test_a_held_lock_refuses_the_order_before_any_change(self) -> None:
        self.hold_lock()
        run = self.apply_staging(self.eligible_staging())
        self.assertEqual(
            (run.status, run.execution),
            (Status.FAILED, Execution.LOCK_CONFLICT),
            run.failure,
        )
        self.assertFalse(self.staged_exists())

    def hold_lock(self) -> None:
        """Hold the mutation lock as a compatible renewal would.

        ``fuser -k`` in the cleanup reaches every process holding the lock file,
        including waiters forked from the holder with an inherited descriptor, so no
        orphaned waiter can keep the lock past the test.
        """
        import time

        self.administer(f"flock -n {LOCK} sleep 60 >/dev/null 2>&1", detach=True)
        self.addCleanup(self.administer, f"fuser -k {LOCK} >/dev/null 2>&1; true")
        deadline = time.monotonic() + 10
        while self.lock_is_free() and time.monotonic() < deadline:
            time.sleep(0.5)
        self.assertFalse(self.lock_is_free())

    def test_a_lost_answer_is_checked_without_another_order(self) -> None:
        from bootstrap.test_apply_remote import _is_inspection

        plan = self.eligible_staging()
        with self.losing(_is_inspection, after=False):
            run = self.apply_staging(plan)
        self.assertEqual(run.status, Status.RECONCILING, run.failure)
        self.wait_terminal(run.unit_name, timeout=600)
        run = self.check(run)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(ApplyRun.objects.count(), 1)
