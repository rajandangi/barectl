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
