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
        self.assertIn("http://" + hostname, caddy)
        self.assertIn("reverse_proxy @php unix//run/haproxy/shop/http.sock", caddy)
        self.assertNotIn("/run/php-fpm", caddy)
        self.assertIn("user = sshop\n", pool)
        self.assertIn("listen = /run/php-fpm/sites/shop/php84/app.sock\n", pool)
        self.assertIn("listen.owner = root\n", pool)
        self.assertIn("listen.group = pshop\n", pool)
        self.assertIn("listen.mode = 0660\n", pool)


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
