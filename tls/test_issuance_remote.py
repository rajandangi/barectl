"""Production orders, HTTPS activation and native renewal on a real disposable server.

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Through the dashboard request, the worker,
Barectl's SSH connection and actual resolvectl, systemd, Certbot and Nginx, with the local
Pebble ACME fixtures standing in for the production authority; the short profile's
certificates are due at once, so the packaged timer's own renewal path can be exercised.
Ground truth is read with ``openssl``, ``journalctl`` and ``docker exec``.
"""

import shlex
import time
from typing import ClassVar, override
from unittest import skipUnless

from django.contrib.auth.models import Permission
from django.test import override_settings

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from discovery import models as discovery
from discovery.fakes import run_worker
from disposable import acme
from operations.models import RemoteOperation
from sites.convention import Stage, render_placeholder, render_site
from sites.test_review_remote import PUT_BACK, SET_ASIDE, create_site, remove_site

from . import native as challenge_native
from .models import (
    ActivationRunResult,
    IssuanceRunResult,
    PlanTlsActivation,
    PlanTlsIssuance,
)
from .test_setup_remote import PURGE, SetupTestCase

Status = RemoteOperation.Status
NAMES = ("shop.test", "www.shop.test")
LIVE = "/etc/letsencrypt/live/shop"


SHORT_AUTHORITY = {
    "directory": acme.SHORT_DIRECTORY,
    "caa": "pebble",
    "name": "Pebble short",
}


@skipUnless(acme.CONFIGURED, "Set BARECTL_SSH_TEST_CONTAINER and BARECTL_ACME_TEST_*")
@override_settings(
    ACME_AUTHORITIES=[SHORT_AUTHORITY], ACME_PRODUCTION_DIRECTORY=acme.SHORT_DIRECTORY
)
class IssuanceTestCase(SetupTestCase):
    php: ClassVar[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        acme.install_trust_and_resolver(cls)

    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in (
            "view_tlsplan",
            "prepare_tlsplan",
            "apply_tlsplan",
            "issue_certificate",
        ):
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
            f"{remove_site('shop', self.php)}; rm -rf /etc/letsencrypt/live/shop "
            "/etc/letsencrypt/archive/shop /etc/letsencrypt/renewal/shop.conf "
            "/etc/letsencrypt/accounts /etc/nginx/conf.d/tls-default-reject.conf; true",
        )

    def issuance_plan(self) -> ConfigurationPlan:
        self.client.post(
            f"/servers/{self.server.pk}/tls/issuance/prepare/",
            {
                "issuance-identifier": "shop",
                "issuance-email": "ops@example.com",
                "issuance-terms": "on",
            },
        )
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def activation_plan(self) -> ConfigurationPlan:
        self.client.post(
            f"/servers/{self.server.pk}/tls/activation/prepare/",
            {"activation-identifier": "shop"},
        )
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def reviewed(self, plan: ConfigurationPlan) -> ConfigurationPlan:
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def applied(self, plan: ConfigurationPlan) -> ApplyRun:
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        run_worker()
        run.refresh_from_db()
        return run

    def on_disk_fingerprint(self) -> str:
        return self.administer(
            f"openssl x509 -outform DER -in {LIVE}/cert.pem | sha256sum | cut -d' ' -f1"
        ).strip()

    def served_fingerprint(self, name: str) -> str:
        """The served certificate's DER sha256, retried while a reload settles."""
        command = (
            "timeout 10 openssl s_client -connect 127.0.0.1:443 "
            f"-servername {shlex.quote(name)} </dev/null 2>/dev/null | openssl x509 "
            "-outform DER 2>/dev/null | sha256sum | cut -d' ' -f1"
        )
        fingerprint = ""
        for _ in range(10):
            fingerprint = self.administer(command).strip()
            if len(fingerprint) == 64:
                return fingerprint
            time.sleep(1)
        return fingerprint

    def http_status(self, path: str) -> str:
        client = challenge_native.status_client(self.php)
        return self.administer(f"{client}; s 127.0.0.1 shop.test {shlex.quote(path)} | head -c 3")


class IssuanceTests(IssuanceTestCase):
    def test_a_site_orders_a_production_certificate(self) -> None:
        plan = self.reviewed(self.issuance_plan())
        self.assertTrue(PlanTlsIssuance.objects.get(plan=plan).payload_bytes)
        run = self.applied(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        result = IssuanceRunResult.objects.get(run=run)
        self.assertEqual(result.names, "\n".join(NAMES))
        self.assertEqual(result.fingerprint, self.on_disk_fingerprint())
        self.assertEqual(result.key_curve, "ecdsa prime256v1")
        self.assertTrue(result.key_matches)
        self.assertTrue(result.renewal)
        self.assertEqual(result.problems, "")
        # Issuance never touches Nginx: the challenge route is still the site's file.
        text = self.administer("cat /etc/nginx/sites-available/shop.conf")
        self.assertIn("acme-challenge", text)
        self.assertNotIn("listen 443", text)

    def test_a_missing_acceptance_is_refused_before_queuing(self) -> None:
        self.client.post(
            f"/servers/{self.server.pk}/tls/issuance/prepare/",
            {"issuance-identifier": "shop", "issuance-email": "ops@example.com"},
        )
        run_worker()
        self.assertFalse(PlanPreparation.objects.filter(action="tls_issuance").exists())

    def test_a_lost_answer_is_checked_without_another_order(self) -> None:
        from bootstrap.test_apply_remote import _is_inspection

        plan = self.reviewed(self.issuance_plan())
        with self.losing(_is_inspection, after=False):
            run = self.applied(plan)
        self.assertEqual(run.status, Status.RECONCILING, run.failure)
        self.wait_terminal(run.unit_name, timeout=600)
        run = self.check(run)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(ApplyRun.objects.count(), 1)


class ActivationTests(IssuanceTestCase):
    def order(self) -> ApplyRun:
        run = self.applied(self.reviewed(self.issuance_plan()))
        self.assertEqual(run.verification, Verification.PASSED, run.failure)
        return run

    def test_a_site_activates_https_and_redirects_http(self) -> None:
        self.order()
        plan = self.reviewed(self.activation_plan())
        activation = PlanTlsActivation.objects.get(plan=plan)
        self.assertTrue(activation.creates_default)
        run = self.applied(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        result = ActivationRunResult.objects.get(run=run)
        self.assertEqual(result.problems, "")
        self.assertTrue(result.rejects_unknown)
        self.assertTrue(result.host_checked)
        on_disk = self.on_disk_fingerprint()
        for name in NAMES:
            self.assertEqual(self.served_fingerprint(name), on_disk, name)
            self.assertIn(f"{name} {on_disk}", result.served)
        # The redirect, the challenge route and the shared rejection server.
        self.assertEqual(self.http_status("/"), "301")
        self.assertEqual(self.http_status("/.well-known/acme-challenge/missing"), "404")
        default = self.administer(
            "stat -c '%U %G %a' /etc/nginx/conf.d/tls-default-reject.conf"
        ).strip()
        self.assertEqual(default, "root root 644")
        self.assertIn(
            "ssl_reject_handshake on",
            self.administer("cat /etc/nginx/conf.d/tls-default-reject.conf"),
        )
        # Fresh discovery reconstructs the activated relationship.
        run_worker()
        from discovery.models import DiscoveryAttempt

        attempt = DiscoveryAttempt.objects.latest("pk")
        site = discovery.SiteObservation.objects.get(identifier="shop")
        self.assertEqual(
            site.stage,
            discovery.SiteStage.REDIRECT,
            f"attempt {attempt.status} {attempt.failure}",
        )
        self.assertEqual(site.certificate_reference, "/etc/letsencrypt/live/shop/fullchain.pem")
        certificate = discovery.SiteCertificateObservation.objects.get(site=site)
        self.assertIn(on_disk, certificate.served)
        if certificate.status == discovery.ObservationOutcome.OBSERVED:
            self.assertEqual(certificate.fingerprint, on_disk)
        else:
            # /etc/letsencrypt is root-only: ordinary discovery names the denial instead of
            # pretending the lineage is absent; an authorized read reconstructs the facts.
            self.assertEqual(certificate.status, discovery.ObservationOutcome.INACCESSIBLE)
            self.assertIn("sudo", certificate.warning)

    def test_a_competing_default_refuses(self) -> None:
        self.order()
        self.addCleanup(
            self.administer,
            "rm -f /etc/nginx/conf.d/competing.conf; nginx -t -q && systemctl reload nginx; true",
        )
        competing = (
            "server {\n\tlisten 443 ssl default_server;\n\tlisten [::]:443 ssl "
            "default_server;\n\tssl_certificate /etc/letsencrypt/live/shop/fullchain.pem;\n"
            "\tssl_certificate_key /etc/letsencrypt/live/shop/privkey.pem;\n}\n"
        )
        self.administer(
            "printf %s " + shlex.quote(competing) + " >/etc/nginx/conf.d/competing.conf "
            "&& nginx -t -q && systemctl reload nginx"
        )
        plan = self.activation_plan()
        self.assertFalse(plan.eligible)
        texts = " ".join(plan.refusals.values_list("text", flat=True))
        self.assertIn("competing.conf", texts)

    def test_a_missing_lineage_refuses(self) -> None:
        plan = self.activation_plan()
        self.assertFalse(plan.eligible)
        self.assertIn("prerequisite", list(plan.refusals.values_list("reason", flat=True)))


class RenewalTests(IssuanceTestCase):
    def test_the_timer_renews_and_deploys_without_a_controller(self) -> None:
        self.applied(self.reviewed(self.issuance_plan()))
        self.applied(self.reviewed(self.activation_plan()))
        before = self.on_disk_fingerprint()
        self.assertEqual(self.served_fingerprint("shop.test"), before)
        # The short profile's certificate is due at once, so the packaged service's own
        # guarded path renews and the deploy hook reloads Nginx.
        self.administer("systemctl start certbot.service")
        deadline = time.monotonic() + 300
        after = before
        while time.monotonic() < deadline:
            after = self.on_disk_fingerprint()
            if after != before:
                break
            time.sleep(2)
        self.assertNotEqual(after, before, "the certificate was not renewed")
        self.assertEqual(self.served_fingerprint("shop.test"), after)
        journal = self.administer("journalctl --no-pager -o cat -u certbot.service | tail -20")
        self.assertIn("barectl-renew: deployed", journal)
        self.assertEqual(self.http_status("/"), "301")
