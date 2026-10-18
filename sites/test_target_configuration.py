"""Target convention contracts at the renderer and native parser boundary."""

from django.test import SimpleTestCase

from .configuration import SiteSettings, render_caddy, render_pool


class TargetConfigurationTests(SimpleTestCase):
    def test_target_site_accepts_a_full_dns_name_and_routes_through_private_admission(
        self,
    ) -> None:
        hostname = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        settings = SiteSettings("shop", (hostname,), "php84")
        caddy = render_caddy(settings)
        pool = render_pool(settings)
        self.assertIn(hostname + " {", caddy)
        self.assertNotIn("http://" + hostname, caddy)
        self.assertIn("reverse_proxy @php unix//run/haproxy/shop/http.sock", caddy)
        self.assertNotIn("/run/php-fpm", caddy)
        self.assertIn("user = sshop\n", pool)
        self.assertIn("listen = /run/php-fpm/sites/shop/php84/app.sock\n", pool)
        self.assertIn("listen.owner = root\n", pool)
        self.assertIn("listen.group = pshop\n", pool)
        self.assertIn("listen.mode = 0660\n", pool)

    def test_an_http_only_site_uses_explicit_http_addresses(self) -> None:
        settings = SiteSettings("shop", ("shop.example.com", "www.example.com"), "php84", False)
        caddy = render_caddy(settings)
        self.assertIn("http://shop.example.com, http://www.example.com {", caddy)


class DnsWarningTests(SimpleTestCase):
    """A DNS mismatch warns and never refuses (issue #376, docs/tls.md)."""

    def test_a_name_that_does_not_resolve_warns(self) -> None:
        from .change import SiteEvidence, dns_warnings

        evidence = SiteEvidence(None, None, None, None, {"local": ["10.0.0.1"], "resolved": {}})
        warnings = dns_warnings(evidence, ("shop.example.com",))
        self.assertTrue(any("shop.example.com" in warning for warning in warnings))

    def test_a_name_resolving_elsewhere_warns_with_the_answer(self) -> None:
        from .change import SiteEvidence, dns_warnings

        evidence = SiteEvidence(
            None,
            None,
            None,
            None,
            {"local": ["10.0.0.1"], "resolved": {"shop.example.com": ["203.0.113.9"]}},
        )
        warnings = dns_warnings(evidence, ("shop.example.com",))
        self.assertTrue(any("203.0.113.9" in warning for warning in warnings))

    def test_a_name_resolving_to_this_server_warns_about_nothing(self) -> None:
        from .change import SiteEvidence, dns_warnings

        evidence = SiteEvidence(
            None,
            None,
            None,
            None,
            {"local": ["10.0.0.1"], "resolved": {"shop.example.com": ["10.0.0.1"]}},
        )
        self.assertEqual(dns_warnings(evidence, ("shop.example.com",)), ())

    def test_an_unreadable_dns_evidence_warns_about_nothing(self) -> None:
        from .change import SiteEvidence, dns_warnings

        self.assertEqual(dns_warnings(SiteEvidence(None, None, None, None, None), ("a.com",)), ())


class SiteMasterStopTests(SimpleTestCase):
    """docs/site-conventions.md: a stop waits for the longest request a pool may run."""

    def test_stop_waits_out_the_longest_supported_request_well_within_the_apply_limit(
        self,
    ) -> None:
        from .serving import fpm_unit, master_config

        settings = SiteSettings("shop", ("shop.example.com",), "php84")
        self.assertIn("request_terminate_timeout = 300s\n", render_pool(settings))
        self.assertIn("process_control_timeout = 300s\n", master_config(settings))
        for entry in ("php84", "php85"):
            unit = fpm_unit(entry)
            self.assertIn("TimeoutStopSec=310s\n", unit)
            self.assertNotIn("infinity", unit)
            self.assertNotIn("SendSIGKILL", unit)
