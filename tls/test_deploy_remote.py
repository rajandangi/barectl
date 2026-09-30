"""Guarded renewal of a real lineage, and its deploy hook, on a disposable server.

Tagged ``ssh``; needs the ACME fixtures ``run-tests.sh`` starts (disposable/acme.py). After a
reviewed setup, the administrator creates a convention site with its challenge route and,
under the mutation lock as a later issuance will, orders a certificate from the short-lived
Pebble, whose certificates are due for renewal at once. A test-only HTTPS server block serves
it. Renewal then runs through certbot.service, as the timer starts it.
"""

import shlex
from typing import ClassVar, override
from unittest import skipUnless

from discovery.releases import SUPPORTED
from disposable import acme
from sites.convention import Stage, render_placeholder, render_site
from sites.test_review_remote import create_site, remove_site

from . import renewal
from .test_renewal_remote import LOCK, RenewalTestCase

Outcome = renewal.Outcome
NAMES = ("shop.test",)
WEBROOT = "/var/lib/letsencrypt/shop"
HTTPS = "/etc/nginx/conf.d/zz-barectl-test-https.conf"
LIVE = "/etc/letsencrypt/live/shop"
SERVED = (
    "openssl s_client -connect 127.0.0.1:443 -servername shop.test </dev/null 2>/dev/null "
    "| openssl x509 -noout -fingerprint -sha256"
)
ON_DISK = f"openssl x509 -noout -fingerprint -sha256 -in {LIVE}/cert.pem"


@skipUnless(acme.CONFIGURED, "Set BARECTL_SSH_TEST_CONTAINER and BARECTL_ACME_TEST_*")
class DeployTests(RenewalTestCase):
    php: ClassVar[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        acme.install_trust_and_resolver(cls)

    @override
    def setUp(self) -> None:
        super().setUp()
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        php = SUPPORTED[release].php
        self.addCleanup(
            self.administer,
            f"rm -f {HTTPS}; {remove_site('shop', php)}; systemctl reload nginx; true",
        )
        self.administer(create_site("shop", NAMES, php))
        placeholder = shlex.quote(render_placeholder("shop"))
        route = shlex.quote(render_site("shop", NAMES, ipv6=True, stage=Stage.CHALLENGE))
        self.administer(
            f"printf %s {placeholder} >/var/www/shop/public/index.html && "
            f"mkdir -p -m 0755 /var/lib/letsencrypt && mkdir -m 0750 {WEBROOT} && "
            f"chown root:www-data {WEBROOT} && "
            f"printf %s {route} >/etc/nginx/sites-available/shop.conf && "
            "nginx -t -q && systemctl reload nginx"
        )
        acme.add_a(self, "shop.test", [acme.server_addresses().ipv4])
        order = (
            f"certbot certonly -n --server {acme.SHORT_DIRECTORY} --webroot -w {WEBROOT} "
            "-d shop.test --cert-name shop --agree-tos --register-unsafely-without-email "
            "--no-eff-email --no-directory-hooks --key-type ecdsa --elliptic-curve secp256r1"
        )
        self.administer(f"flock -n {LOCK} {order} >/dev/null 2>&1")
        https = (
            "server {\n\tlisten 443 ssl;\n\tserver_name shop.test;\n"
            f"\tssl_certificate {LIVE}/fullchain.pem;\n\tssl_certificate_key {LIVE}/privkey.pem;\n"
            '\treturn 200 "shop over https\\n";\n}\n'
        )
        self.administer(
            f"printf %s {shlex.quote(https)} >{HTTPS} && nginx -t -q && systemctl reload nginx && "
            # Due now on both releases, whatever each version's default window.
            "sed -i '1i renew_before_expiry = 30 days' /etc/letsencrypt/renewal/shop.conf"
        )
        self.first = self.administer(ON_DISK)
        self.assertEqual(self.administer(SERVED), self.first)

    def target(self) -> str:
        return self.administer(f"readlink {LIVE}/cert.pem").strip()

    def test_a_due_certificate_renews_under_the_lock_and_is_served(self) -> None:
        shown = self.renew()
        self.assertEqual((shown["Result"], shown["ExecMainStatus"]), ("success", "0"))
        self.assertEqual(self.target(), "../../archive/shop/cert2.pem")
        renewed = self.administer(ON_DISK)
        self.assertNotEqual(renewed, self.first)
        self.assertEqual(self.administer(SERVED), renewed)
        self.assertIn(f"barectl-renew: deployed {LIVE}", self.renewal_journal())
        self.assertTrue(self.lock_is_free())

    def test_a_configuration_nginx_refuses_is_not_reloaded_and_fails_the_run(self) -> None:
        wrapper = (
            "#!/bin/sh\n"
            '[ "$1" = -t ] && { echo "barectl test: invalid" >&2; exit 1; }\n'
            'exec /run/barectl-nginx.real "$@"\n'
        )
        self.addCleanup(
            self.administer, "umount /usr/sbin/nginx 2>/dev/null; rm -f /run/barectl-nginx*"
        )
        self.administer(
            "cp /usr/sbin/nginx /run/barectl-nginx.real && "
            f"printf %s {shlex.quote(wrapper)} >/run/barectl-nginx && chmod 755 /run/barectl-nginx "
            "&& mount --bind /run/barectl-nginx /usr/sbin/nginx"
        )
        workers = self.administer("pgrep -P $(cat /run/nginx.pid) | sort")
        shown = self.renew()
        self.assertEqual(
            (shown["Result"], shown["ExecMainStatus"]), ("exit-code", str(Outcome.NOT_DEPLOYED))
        )
        journal = self.renewal_journal()
        self.assertIn("barectl-deploy: nginx -t refused the configuration", journal)
        self.assertIn(f"barectl-renew: not deployed {LIVE}", journal)
        # Renewed on disk, still serving the earlier certificate, and never reloaded.
        self.assertEqual(self.target(), "../../archive/shop/cert2.pem")
        self.assertEqual(self.administer(SERVED), self.first)
        self.assertEqual(self.administer("pgrep -P $(cat /run/nginx.pid) | sort"), workers)

    def test_a_failed_reload_fails_the_run(self) -> None:
        directory = "/run/systemd/system/nginx.service.d"
        self.addCleanup(self.administer, f"rm -rf {directory}; systemctl daemon-reload")
        self.administer(
            f"mkdir -p {directory} && printf '[Service]\\nExecReload=\\nExecReload=/bin/false\\n' "
            f">{directory}/barectl-test.conf && systemctl daemon-reload"
        )
        shown = self.renew()
        self.assertEqual(
            (shown["Result"], shown["ExecMainStatus"]), ("exit-code", str(Outcome.NOT_DEPLOYED))
        )
        self.assertIn("barectl-deploy: reloading nginx failed", self.renewal_journal())
        self.assertEqual(self.administer(SERVED), self.first)
