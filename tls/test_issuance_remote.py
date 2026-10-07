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
from bootstrap.test_journey_remote import SECOND_DEVICE, SecondDevice
from bootstrap.test_mariadb_remote import INSTALL_MARIADB
from bootstrap.test_postgresql_remote import REMOVE_POSTGRESQL
from dashboard.testing import TEST_MANIFEST
from databases.test_bindings_remote import PERMISSIONS as DATABASE_PERMISSIONS
from discovery import models as discovery
from discovery.fakes import run_worker
from discovery.test_remote import setting
from disposable import acme
from operations.models import RemoteOperation
from sites.convention import Stage, render_placeholder, render_pool, render_site
from sites.test_review_remote import PUT_BACK, SET_ASIDE, create_site, remove_site

from . import native as challenge_native
from .models import (
    ActivationRunResult,
    IssuanceRunResult,
    PlanTlsActivation,
    PlanTlsIssuance,
    RunTlsActivation,
    RunTlsIssuance,
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
    def test_create_and_install_runs_all_steps_from_one_request(self) -> None:
        from discovery.services import request_discovery

        from .models import CertificateInstallation

        self.user.user_permissions.add(Permission.objects.get(codename="view_siteobservation"))
        self.administer(PURGE)
        self.administer(
            f"printf %s {shlex.quote(render_site('shop', NAMES, ipv6=True))} "
            ">/etc/nginx/sites-available/shop.conf && nginx -t -q && systemctl reload nginx; "
            "rm -rf /var/lib/letsencrypt/shop"
        )
        request_discovery(self.server)
        run_worker()
        unread = discovery.SiteObservation.objects.filter(identifier="shop").latest("pk")
        self.assertEqual(unread.outcome, discovery.ObservationOutcome.INACCESSIBLE)
        self.addCleanup(self.administer, f"gpasswd -d {setting('USER')} shadow >/dev/null")
        self.administer(f"usermod -aG shadow {setting('USER')}")
        request_discovery(self.server)
        run_worker()
        observed = discovery.SiteObservation.objects.filter(identifier="shop").latest("pk")
        self.assertEqual(
            (observed.state, observed.outcome),
            (discovery.SiteState.MANAGED, discovery.ObservationOutcome.OBSERVED),
            observed.expected,
        )
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/install/",
            {
                "installation-identifier": "shop",
                "installation-email": "ops@example.com",
                "installation-snapshot": str(self.server.snapshots.latest("pk").pk),
            },
        )
        self.assertEqual(response.status_code, 302)
        run_worker()
        installation = CertificateInstallation.objects.get()
        self.assertEqual(
            installation.status, CertificateInstallation.Status.SUCCEEDED, installation.failure
        )
        self.assertEqual(installation.steps.count(), 4)
        self.assertEqual(
            installation.steps.filter(run__verification=Verification.PASSED).count(), 4
        )
        self.assertEqual(installation.steps.filter(run__failure="").count(), 4)
        for name in NAMES:
            self.assertEqual(self.served_fingerprint(name), self.on_disk_fingerprint())
        before = ApplyRun.objects.count()
        self.client.post(
            f"/servers/{self.server.pk}/tls/install/",
            {
                "installation-identifier": "shop",
                "installation-email": "ops@example.com",
                "installation-snapshot": str(self.server.snapshots.latest("pk").pk),
            },
        )
        run_worker()
        again = CertificateInstallation.objects.first()
        assert again is not None  # noqa: S101 - the second request was accepted
        self.assertEqual(
            again.status,
            CertificateInstallation.Status.SUCCEEDED,
            (
                again.failure,
                list(again.steps.values_list("preparation__action", "run__pk")),
                list(ConfigurationPlan.objects.values_list("action", "no_changes")),
            ),
        )
        self.assertEqual(ApplyRun.objects.count(), before)
        original = self.administer("cat /etc/letsencrypt/renewal/shop.conf")
        for edit in (
            "sed -i '/^authenticator =/a pre_hook = /bin/true'",
            "sed -i 's|^server =.*|server = https://foreign.test/directory|'",
        ):
            self.administer(
                f"printf %s {shlex.quote(original)} >/etc/letsencrypt/renewal/shop.conf; "
                f"{edit} /etc/letsencrypt/renewal/shop.conf"
            )
            refused = self.setup_plan()
            self.assertFalse(refused.eligible)
            self.assertEqual(ApplyRun.objects.count(), before)
        self.administer(
            "mv /etc/letsencrypt/renewal /etc/letsencrypt/renewal-original; "
            "touch /etc/letsencrypt/renewal"
        )
        try:
            self.assertFalse(self.setup_plan().eligible)
        finally:
            self.administer(
                "rm /etc/letsencrypt/renewal; "
                "mv /etc/letsencrypt/renewal-original /etc/letsencrypt/renewal"
            )

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

    def test_the_order_request_authorizes_terms_without_a_checkbox(self) -> None:
        self.client.post(
            f"/servers/{self.server.pk}/tls/issuance/prepare/",
            {"issuance-identifier": "shop", "issuance-email": "ops@example.com"},
        )
        run_worker()
        plan = ConfigurationPlan.objects.filter(action="tls_issuance").latest("pk")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertFalse(ApplyRun.objects.exists())

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
    def test_selected_socket_survives_native_issuance_and_https_activation(self) -> None:
        source = "/etc/nginx/sites-available/shop.conf"
        route = render_site("shop", NAMES, ipv6=True, stage=Stage.CHALLENGE, php_version=self.php)
        pool = render_pool("shop", php_version=self.php)
        self.administer(
            f"printf %s {shlex.quote(route)} >{source}; "
            f"printf %s {shlex.quote(pool)} >/etc/php/{self.php}/fpm/pool.d/shop.conf; "
            f"php-fpm{self.php} -t && systemctl reload php{self.php}-fpm; "
            "nginx -t && systemctl reload nginx"
        )
        order = self.order()
        issuance = RunTlsIssuance.objects.get(run=order)
        self.assertEqual((issuance.php_version, issuance.site_revision), (self.php, 4))
        plan = self.reviewed(self.activation_plan())
        run = self.applied(plan)
        self.assertEqual(
            (run.execution, run.verification),
            (Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        activation = RunTlsActivation.objects.get(run=run)
        self.assertEqual((activation.php_version, activation.site_revision), (self.php, 4))
        self.assertEqual(
            self.administer(f"cat {source}"),
            render_site("shop", NAMES, ipv6=True, stage=Stage.REDIRECT, php_version=self.php),
        )

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
        failure = run.failure
        if run.status != Status.SUCCEEDED:
            failure += "\n" + self.administer(
                f"journalctl --no-pager -n 100 -u {run.unit_name} -u nginx.service "
                "-u certbot.service; tail -n 30 /var/log/nginx/error.log"
            )
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            failure,
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
        # The activated site is one managed state; other conf.d files are not read. The
        # password lock may be unreadable to this SSH user, which is never drift.
        self.assertEqual(site.state, discovery.SiteState.MANAGED, site.expected)
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


@skipUnless(acme.CONFIGURED, "Set BARECTL_SSH_TEST_CONTAINER and BARECTL_ACME_TEST_*")
@override_settings(
    ACME_AUTHORITIES=[SHORT_AUTHORITY], ACME_PRODUCTION_DIRECTORY=acme.SHORT_DIRECTORY
)
class SecondDeviceTests(IssuanceTestCase):
    """The v0.3 relationships reconstruct on another installation with its own database."""

    def second_device(self) -> SecondDevice:
        import json
        import subprocess
        import sys

        directory = self.directory / "second-device"
        directory.mkdir()
        config = directory / "config"
        config.write_text(
            f"Host disposable-second\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User {setting('USER')}\n  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n"
            f"  IdentityFile {setting('SECOND_KEY')}\n",
            encoding="utf-8",
        )
        completed = subprocess.run(  # noqa: S603 - the test's own script
            [
                sys.executable,
                "-c",
                SECOND_DEVICE,
                str(directory / "db.sqlite3"),
                str(config),
                str(TEST_MANIFEST),
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-3000:])
        return SecondDevice(**json.loads(completed.stdout.strip().splitlines()[-1]))

    def test_the_activated_site_and_binding_reconstruct(self) -> None:
        self.applied(self.reviewed(self.issuance_plan()))
        self.applied(self.reviewed(self.activation_plan()))
        self.administer(INSTALL_MARIADB)
        self.administer(
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o "
            f"APT::Install-Recommends=0 php{self.php}-mysql >/dev/null"
        )
        for codename in DATABASE_PERMISSIONS:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": "database_mariadb", "identifier": "shop"},
        )
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        run_worker()
        run.refresh_from_db()
        self.assertEqual(
            (run.status, run.verification),
            (Status.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        # A second site on the other engine, then the same reconstruction.
        self.addCleanup(self.administer, remove_site("legacy", self.php))
        self.administer(create_site("legacy", ("legacy.test",), self.php))
        self.administer(
            f"printf %s {shlex.quote(render_placeholder('legacy'))} "
            ">/var/www/legacy/public/index.html"
        )
        # The disposable image carries extra clusters; the profile's established state is
        # the release default's main cluster alone.
        self.administer(REMOVE_POSTGRESQL)
        self.administer(
            "export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq -o "
            f"APT::Install-Recommends=0 postgresql php{self.php}-pgsql >/dev/null"
        )
        self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": "database_postgresql", "identifier": "legacy"},
        )
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        run_worker()
        run.refresh_from_db()
        self.assertEqual(
            (run.status, run.verification),
            (Status.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        device = self.second_device()
        self.assertEqual(device.discovery, "succeeded")
        self.assertEqual(device.site_stages.get("shop"), "redirect")
        certificate = device.site_certificates["shop"]
        self.assertIn(certificate["status"], {"observed", "inaccessible"})
        self.assertEqual(certificate["reference"], "/etc/letsencrypt/live/shop/fullchain.pem")
        if certificate["status"] == "observed":
            self.assertEqual(certificate["fingerprint"], self.on_disk_fingerprint())
        # Ordinary unprivileged discovery names the root-only catalog inaccessible; the
        # authorized read-only inspection reconstructs the binding without key bytes.
        binding = device.site_bindings["shop"]
        if binding["status"] == "observed":
            self.assertEqual(binding["engine"], "mariadb")
            self.assertTrue(binding["conforms"])
        else:
            self.assertEqual(binding["status"], "inaccessible")
        self.assertEqual(device.catalog["shop"]["engine"], "mariadb")
        self.assertTrue(device.catalog["shop"]["conforms"])
        self.assertEqual(device.activation["fingerprint"], self.on_disk_fingerprint())
        self.assertTrue(device.activation["no_changes"])
        legacy = device.site_bindings["legacy"]
        if legacy["status"] == "observed":
            self.assertEqual(legacy["engine"], "postgresql")
            self.assertTrue(legacy["conforms"])
        self.assertEqual(device.catalog["legacy"]["engine"], "postgresql")
        self.assertTrue(device.catalog["legacy"]["conforms"])
        # The first device's records are gone; the second holds only what it read.
        self.assertEqual(device.runs, 0)
        self.assertFalse(device.activity_applies)
