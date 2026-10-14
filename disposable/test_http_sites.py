"""Real Caddy parser, publication and plain-PHP site behavior."""

import shlex

from django.test import tag

from sites.configuration import SiteSettings, render_caddy

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteNativeBehavior(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s4"

    def test_http_renderer_validates_as_the_caddy_service_identity(self) -> None:
        settings = SiteSettings("s4alpha", ("s4alpha.example.com",), "php84")
        self.native(
            "install -d -o caddy -g caddy -m 750 /var/www/s4alpha/logs; "
            "install -d -o root -g caddy -m 750 /run/s4candidate/sites"
        )
        self.native(
            "cp /etc/caddy/Caddyfile /run/s4candidate/Caddyfile; "
            "chown root:caddy /run/s4candidate/Caddyfile; chmod 640 /run/s4candidate/Caddyfile"
        )
        self.native(
            "printf %s "
            + shlex.quote(render_caddy(settings))
            + " >/run/s4candidate/sites/s4alpha.caddy; "
            "chown root:caddy /run/s4candidate/sites/s4alpha.caddy; "
            "chmod 640 /run/s4candidate/sites/s4alpha.caddy"
        )
        self.native(
            "runuser -u caddy -- /nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
            "--config /run/s4candidate/Caddyfile --adapter caddyfile"
        )
