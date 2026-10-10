"""Native WordPress certificate preservation (docs/wordpress.md, docs/tls.md)."""

import shlex
import time
from typing import override
from unittest import skipUnless

from django.contrib.auth.models import Permission
from django.test import override_settings

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from discovery.fakes import run_worker
from disposable import acme
from operations.models import RemoteOperation
from sites.convention import Application, Stage, render_pool, render_site
from tls.models import RunTlsActivation
from tls.native_testing import PURGE

from .install_apply_remote_testing import SITE_FILE, USER, InstallApplyTestCase
from .install_remote_testing import (
    DATABASE,
    IDENTIFIER,
    LINEAGE,
    NAME,
    NAMES,
    PRIVATE,
    PUBLIC,
    put,
)

Status = RemoteOperation.Status
SHORT_AUTHORITY = {
    "directory": acme.SHORT_DIRECTORY,
    "caa": "pebble",
    "name": "Pebble short",
}
CHALLENGE = "/.well-known/acme-challenge/wordpress-preserved"
WEBROOT = f"/var/lib/letsencrypt/{IDENTIFIER}"


@skipUnless(acme.CONFIGURED, "Set BARECTL_SSH_TEST_CONTAINER and BARECTL_ACME_TEST_*")
@override_settings(
    ACME_AUTHORITIES=[SHORT_AUTHORITY], ACME_PRODUCTION_DIRECTORY=acme.SHORT_DIRECTORY
)
class InstalledWordpressTlsCase(InstallApplyTestCase):
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
        self.administer(PURGE)
        self.addCleanup(self.administer, PURGE)
        self.addCleanup(self.administer, "rm -f /etc/nginx/conf.d/tls-default-reject.conf; true")
        self.publish_site(Stage.CHALLENGE, application=Application.PHP)
        pool = f"/etc/php/{self.php}/fpm/pool.d/{IDENTIFIER}.conf"
        self.administer(
            put(pool, render_pool(IDENTIFIER, php_version=self.php), "root", "root", "644")
            + f" && php-fpm{self.php} -t && systemctl reload php{self.php}-fpm"
        )
        self.successful(self.apply(self.tls_plan("certbot")))
        self.administer(
            "install -d -m 755 /var/lib/letsencrypt && "
            f"install -d -o root -g www-data -m 750 {WEBROOT}"
        )
        addresses = acme.server_addresses()
        for name in NAMES:
            acme.add_a(self, name, [addresses.ipv4])
            acme.add_aaaa(self, name, [addresses.ipv6])
        self.successful(self.apply(self.tls_plan("issuance")))
        self.successful(self.apply(self.tls_plan("activation")))
        self.successful(self.apply_install(self.eligible()))
        self.administer(
            f"install -d -o {USER} -g www-data -m 755 {PUBLIC}/wp-content/uploads && "
            f"printf '%s' '<?php echo \"must not execute\";' >{PUBLIC}/wp-content/uploads/x.php && "
            f"printf '%s' 'private content' >{PUBLIC}/.hidden && "
            f"chown {USER}:www-data {PUBLIC}/wp-content/uploads/x.php {PUBLIC}/.hidden && "
            f"install -d -o root -g www-data -m 750 {WEBROOT}/.well-known "
            f"{WEBROOT}/.well-known/acme-challenge && "
            f"printf '%s' 'wordpress challenge preserved' >{WEBROOT}{CHALLENGE}"
        )

    def tls_plan(self, action: str) -> ConfigurationPlan:
        data = (
            {"issuance-identifier": IDENTIFIER, "issuance-email": "ops@example.com"}
            if action == "issuance"
            else {"activation-identifier": IDENTIFIER}
            if action == "activation"
            else {}
        )
        response = self.client.post(f"/servers/{self.server.pk}/tls/{action}/prepare/", data)
        self.assertEqual(response.status_code, 302, response.content[:300])
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def successful(self, run: ApplyRun) -> None:
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            f"{run.failure}\n{self.journal_tail(run)}",
        )

    def publish_site(self, stage: Stage, *, application: Application) -> None:
        text = render_site(
            IDENTIFIER,
            NAMES,
            ipv6=True,
            stage=stage,
            php_version=self.php,
            application=application,
            canonical=NAME if application.wordpress else NAMES[0],
        )
        self.administer(
            put(SITE_FILE, text, "root", "root", "644")
            + " && nginx -t -q && systemctl reload nginx"
        )

    def application_state(self) -> dict[str, str]:
        database = (
            "mariadb-dump --no-defaults --protocol=socket --single-transaction "
            f"--skip-comments --skip-dump-date {DATABASE} | sha256sum"
        )
        reads = {
            "files": f"find {PUBLIC} {PRIVATE} -type f -exec sha256sum {{}} + | sort",
            "attributes": f"find {PUBLIC} {PRIVATE} -printf '%y %m %U %G %p\\n' | sort",
            "pool": f"sha256sum /etc/php/{self.php}/fpm/pool.d/{IDENTIFIER}.conf",
            "database": f"bash -o pipefail -c {shlex.quote(database)}",
            "challenge": f"sha256sum {WEBROOT}{CHALLENGE}",
        }
        return {name: self.administer(command) for name, command in reads.items()}

    def fingerprint(self, *, served_name: str = "") -> str:
        certificate = (
            "timeout 10 openssl s_client -connect 127.0.0.1:443 "
            f"-servername {shlex.quote(served_name)} </dev/null 2>/dev/null | "
            "openssl x509 -outform DER 2>/dev/null"
            if served_name
            else f"openssl x509 -outform DER -in {LINEAGE}/cert.pem"
        )
        return self.administer(f"{certificate} | sha256sum | cut -d' ' -f1").strip()

    def assert_public_application(self) -> None:
        for path in ("/", "/wp-login.php"):
            self.assertEqual(self.curl(path), "200", path)
        query = self.administer(
            f"curl -sk --max-time 20 --resolve {NAME}:443:127.0.0.1 -o /dev/null "
            "-w '%{http_code}' "
            f"{shlex.quote(f'https://{NAME}/?p=1&wordpress-preserved=1')}"
        )
        self.assertEqual(query, "200")
        for path in ("/wp-config.php", "/wp-content/uploads/x.php", "/.hidden"):
            self.assertEqual(self.curl(path), "403", path)
        path = "/wp-login.php?wordpress-preserved=1"
        for name in NAMES:
            headers = self.administer(
                f"curl -sS --max-time 20 -H 'Host: {name}' -D - -o /dev/null "
                f"{shlex.quote(f'http://127.0.0.1{path}')}"
            )
            self.assert_redirect(headers, path)
            self.assertEqual(self.curl(CHALLENGE, host=name, scheme="http"), "200")
            body = self.administer(
                f"curl -sS --max-time 20 -H 'Host: {name}' http://127.0.0.1{CHALLENGE}"
            )
            self.assertEqual(body, "wordpress challenge preserved")
        alias = NAMES[0]
        headers = self.administer(
            f"curl -sk --max-time 20 --resolve {alias}:443:127.0.0.1 -D - -o /dev/null "
            f"{shlex.quote(f'https://{alias}{path}')}"
        )
        self.assert_redirect(headers, path)

    def assert_redirect(self, headers: str, path: str) -> None:
        self.assertIn("HTTP/1.1 301", headers)
        self.assertIn(f"Location: https://{NAME}{path}\n", headers.replace("\r", ""))

    def test_the_timer_renews_an_installed_wordpress_certificate_without_a_controller(self) -> None:
        before = self.application_state()
        site = self.administer(f"cat {SITE_FILE}")
        timer = self.administer("systemctl show -p UnitFileState -p ActiveState certbot.timer")
        self.assertEqual(
            dict(line.split("=", 1) for line in timer.splitlines()),
            {"UnitFileState": "enabled", "ActiveState": "active"},
        )
        original = self.fingerprint()
        for name in NAMES:
            self.assertEqual(self.fingerprint(served_name=name), original)
        self.administer("systemctl start certbot.service")
        deadline = time.monotonic() + 300
        renewed = original
        while renewed == original and time.monotonic() < deadline:
            renewed = self.fingerprint()
            if renewed == original:
                time.sleep(2)
        journal = self.administer("journalctl -u certbot.service -o cat --no-pager")
        self.assertNotEqual(renewed, original, journal[-3000:])
        shown = self.administer("systemctl show -p Result -p ExecMainStatus certbot.service")
        self.assertEqual(
            dict(line.split("=", 1) for line in shown.splitlines()),
            {"Result": "success", "ExecMainStatus": "0"},
            journal[-3000:],
        )
        for name in NAMES:
            self.assertEqual(self.fingerprint(served_name=name), renewed, name)
        self.assertIn(f"barectl-renew: deployed {LINEAGE}", journal)
        self.assertTrue(self.lock_is_free())
        self.assertEqual(self.administer(f"cat {SITE_FILE}"), site)
        self.assertEqual(self.application_state(), before)
        self.assert_public_application()

    def test_tls_activation_preserves_installed_wordpress_and_the_selected_php_branch(self) -> None:
        ready = self.administer(f"cat {SITE_FILE}")
        before = self.application_state()
        self.publish_site(Stage.HTTPS, application=Application.WORDPRESS)
        plan = self.tls_plan("activation")
        run = self.apply(plan)
        self.successful(run)
        activated = RunTlsActivation.objects.get(run=run)
        self.assertEqual((activated.php_version, activated.site_revision), (self.php, 4))
        self.assertEqual(self.administer(f"cat {SITE_FILE}"), ready)
        self.assertEqual(self.application_state(), before)
        for name in NAMES:
            self.assertEqual(self.fingerprint(served_name=name), self.fingerprint(), name)
        self.assert_public_application()
