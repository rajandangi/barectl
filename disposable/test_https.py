"""HTTPS by default, certificate state and the HTTP-only option (issue #376).

docs/quality.md#native-layer. One lane server issues a real certificate from the lane's
Pebble ACME server, redirects HTTP to HTTPS, keeps the ACME challenge path reachable, keeps
the unknown-host catch-all, exposes only SSH/80/443, and reports the certificate state a
fresh controller reconstructs. A second, HTTP-only site proves the opt-out. The lane's DNS
resolves the fixture domain to the server itself, so the review's DNS check agrees.
"""

import json
import os
import shlex

from django.test import tag

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

DOMAIN = "site.fixture.test"
HTTP_DOMAIN = "s11beta.example.com"
ALIAS_DOMAIN = "s11alias.example.com"


@tag(SCENARIO_TAG)
class HttpsSite(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s11"
    # No transcript: this scenario proves live issuance against the lane's Pebble.

    def caddyfile(self, acme_host: str) -> str:
        return (
            "{\n"
            "\tadmin unix//run/caddy/admin.sock|0600\n"
            f"\tacme_ca https://{acme_host}:14000/dir\n"
            "\tacme_ca_root /etc/caddy/pebble.minica.pem\n"
            "\tservers {\n\t\tstrict_sni_host on\n\t}\n"
            "}\n"
            "import sites/*.caddy\n"
            ":80 {\n\trespond 404\n}\n"
        )

    def adapted_emails(self) -> set[str]:
        value = json.loads(
            self.native(
                "/nix/var/nix/profiles/barectl/caddy/bin/caddy adapt "
                "--config /etc/caddy/Caddyfile --adapter caddyfile"
            )
        )
        return {
            str(issuer["email"])
            for policy in value.get("apps", {})
            .get("tls", {})
            .get("automation", {})
            .get("policies", [])
            for issuer in policy.get("issuers", [])
            if "email" in issuer
        }

    def reissue(self) -> str:
        """Obtain the fixture name's certificate afresh after Caddy's storage is cleared."""
        self.native("rm -rf /var/lib/caddy/.local/share/caddy/certificates")
        self.native("systemctl restart caddy.service")
        return self.native(
            "for attempt in $(seq 1 30); do "
            "if curl --silent --show-error --fail --max-time 10 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/; then exit 0; fi; "
            "sleep 2; done; exit 1"
        )

    def install_acme(self) -> None:
        root = os.environ["BARECTL_FIXTURE_ACME_ROOT"]
        host = os.environ["BARECTL_FIXTURE_ACME_HOST"]
        with open(root, encoding="utf-8") as handle:
            certificate = handle.read()
        original = self.native("cat /etc/caddy/Caddyfile")
        self.addCleanup(
            self.native,
            "printf %s " + shlex.quote(original) + " >/etc/caddy/Caddyfile; systemctl reload caddy",
        )
        self.native(
            "printf %s "
            + shlex.quote(certificate)
            + " >/etc/caddy/pebble.minica.pem; chmod 644 /etc/caddy/pebble.minica.pem"
        )
        self.native("printf %s " + shlex.quote(self.caddyfile(host)) + " >/etc/caddy/Caddyfile")
        self.native(
            "/nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
            "--config /etc/caddy/Caddyfile --adapter caddyfile"
        )
        self.native("chown root:root /etc/caddy/Caddyfile; chmod 644 /etc/caddy/Caddyfile")
        self.native("systemctl reload caddy")

    def test_1_a_new_site_is_https_with_redirect_and_certificate_state(self) -> None:
        from discovery.observations import collect
        from operations.inputs import PreparationInputs
        from sites import change, observation

        self.install_acme()
        inputs = PreparationInputs("php84", "s11alpha", (DOMAIN,), https=True)
        apply_change(self, change.CREATE_SITE, inputs)

        served = self.native(
            "curl --silent --show-error --fail --max-time 20 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/"
        )
        self.assertIn("s11alpha", served)
        issuer = self.native(
            f"echo | openssl s_client -connect 127.0.0.1:443 -servername {DOMAIN} "
            "2>/dev/null | openssl x509 -noout -issuer"
        )
        self.assertIn("Pebble", issuer)

        redirect = self.native(
            "curl --silent --output /dev/null --write-out '%{http_code} %{redirect_url}' "
            f"-H 'Host: {DOMAIN}' http://127.0.0.1/"
        )
        code, _, location = redirect.partition(" ")
        self.assertEqual(code, "308", redirect)
        self.assertEqual(location.strip(), f"https://{DOMAIN}/", redirect)

        # The issued certificate itself proves Caddy's challenge path worked; with no
        # challenge in flight the path redirects like any other HTTP request.

        unknown_http = self.native(
            "curl --silent --output /dev/null --write-out '%{http_code}' "
            "-H 'Host: barectl-unknown.invalid' http://127.0.0.1/"
        )
        self.assertEqual(unknown_http.strip(), "404")
        unknown_https = self.native(
            "curl --silent --output /dev/null --write-out '%{http_code}' --insecure "
            "--max-time 10 --resolve barectl-unknown.invalid:443:127.0.0.1 "
            "https://barectl-unknown.invalid/ || echo refused"
        )
        self.assertNotIn("200", unknown_https)

        ports = {
            address.rsplit(":", 1)[-1]
            for address in self.native("ss -Hlnptu | awk '{print $5}'").split()
            if address
            and not address.startswith("127.")
            and not address.startswith("[::1]")
            and not address.startswith("[::ffff:127.")
        }
        self.assertLessEqual(ports, {"22", "80", "443"}, ports)

        with self.shell() as shell:
            value = observation.read(shell, "s11alpha", "php84", site_only=True)
            if value is None:
                self.fail("The created HTTPS site could not be read.")
            site = next(row for row in value["sites"] if row["identifier"] == "s11alpha")
            certificate = site["certificate"]
            if not isinstance(certificate, dict):
                self.fail("The site's certificate evidence is missing.")
            self.assertTrue(site["https"])
            self.assertEqual(certificate["state"], "issued")
            self.assertIn("Pebble", str(certificate["issuer"]))
            reconstructed = collect(shell)
            observed = next(
                row for row in reconstructed.sites.value if row.identifier == "s11alpha"
            )
            self.assertTrue(observed.https)
            self.assertIsNotNone(observed.certificate)
            if observed.certificate is not None:
                self.assertEqual(observed.certificate.state, "issued")
            repeated = change.review(change.inspect(shell, inputs), inputs)
            self.assertTrue(repeated.no_changes, repeated.refusals)

        # The optional certificate contact email is a Server Setting. It never gates site
        # creation, and Caddy keeps issuing with and without it (Phase B #444).
        from bootstrap.certificate_email import SET_CERTIFICATE_EMAIL

        self.assertEqual(self.adapted_emails(), set())
        apply_change(
            self,
            SET_CERTIFICATE_EMAIL,
            PreparationInputs(certificate_email="ops@fixture.test"),
        )
        self.assertEqual(self.adapted_emails(), {"ops@fixture.test"})
        # Discovery reads the rendered main configuration, so a fresh controller sees the
        # setting without a Barectl marker.
        with self.shell() as shell:
            discovered = collect(shell)
        self.assertEqual(discovered.certificate_email_state, "set")
        self.assertEqual(discovered.certificate_email, "ops@fixture.test")
        # The fixture's own ACME settings survive the publication of the main configuration.
        self.assertIn("acme_ca", self.native("cat /etc/caddy/Caddyfile"))
        self.assertIn("s11alpha", self.reissue())
        apply_change(self, SET_CERTIFICATE_EMAIL, PreparationInputs(certificate_email=""))
        self.assertEqual(self.adapted_emails(), set())
        with self.shell() as shell:
            discovered = collect(shell)
        self.assertEqual(discovered.certificate_email_state, "absent")
        self.assertEqual(discovered.certificate_email, "")
        self.assertIn("acme_ca", self.native("cat /etc/caddy/Caddyfile"))
        self.assertIn("s11alpha", self.reissue())

    def test_2_an_http_only_site_opts_out_and_serves_on_http(self) -> None:
        from operations.inputs import PreparationInputs
        from sites import change, observation

        self.install_acme()
        inputs = PreparationInputs("php84", "s11beta", (HTTP_DOMAIN,), https=False)
        apply_change(self, change.CREATE_SITE, inputs)
        served = self.native(
            f"curl --silent --show-error --fail -H 'Host: {HTTP_DOMAIN}' http://127.0.0.1/"
        )
        self.assertIn("s11beta", served)
        with self.shell() as shell:
            value = observation.read(shell, "s11beta", "php84", site_only=True)
            if value is None:
                self.fail("The created HTTP-only site could not be read.")
            site = next(row for row in value["sites"] if row["identifier"] == "s11beta")
            certificate = site["certificate"]
            if not isinstance(certificate, dict):
                self.fail("The site's certificate evidence is missing.")
            self.assertFalse(site["https"])
            self.assertEqual(certificate["state"], "http")

        # One reviewed change adds an alias; both names serve (Phase B #442). The lane's DNS
        # fixture resolves only the fixture domain for HTTPS, so this stays HTTP and the
        # HTTPS transition is covered by the fast review tests.
        from sites import domains_change

        apply_change(
            self,
            domains_change.SET_SITE_DOMAINS,
            PreparationInputs(
                identifier="s11beta",
                names=(HTTP_DOMAIN, ALIAS_DOMAIN),
                https=False,
                domains=True,
            ),
            timeout=60,
        )
        for name in (HTTP_DOMAIN, ALIAS_DOMAIN):
            served = self.native(
                f"curl --silent --show-error --fail -H 'Host: {name}' http://127.0.0.1/"
            )
            self.assertIn("s11beta", served)
        with self.shell() as shell:
            value = observation.read(shell, "s11beta", "php84", site_only=True)
            if value is None:
                self.fail("The changed site could not be read.")
            site = next(row for row in value["sites"] if row["identifier"] == "s11beta")
            self.assertFalse(site["https"])
            self.assertEqual(site["names"], [HTTP_DOMAIN, ALIAS_DOMAIN])
            self.assertEqual(site["serving_form"], "plain")

    def test_3_the_main_configuration_keeps_the_unknown_host_catch_all(self) -> None:
        self.install_acme()
        code = self.native(
            "curl --silent --output /dev/null --write-out '%{http_code}' "
            "-H 'Host: barectl-unknown.invalid' http://127.0.0.1/"
        )
        self.assertEqual(code.strip(), "404")
        self.native(
            "/nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
            "--config /etc/caddy/Caddyfile --adapter caddyfile"
        )
