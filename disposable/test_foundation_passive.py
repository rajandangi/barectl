"""Discovery must not provision logging or request an unknown application route."""

import shlex

from django.test import tag

from bootstrap import foundation

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class PassiveFoundationDiscovery(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""

    def test_unknown_configuration_is_inspected_without_provisioning_or_http(self) -> None:
        configuration = """{
 admin unix//run/caddy/admin.sock|0600
 auto_https off
 servers {
  strict_sni_host on
 }
}
:80 {
 log {
  output file /var/lib/caddy/access-canary.log
 }
 respond 200
}
"""
        self.native(
            f"set -e; printf %s {shlex.quote(configuration)} >/etc/caddy/Caddyfile; "
            "systemctl reload caddy.service; "
            "truncate -s 0 /var/lib/caddy/access-canary.log; "
            "sed -i 's/access-canary/validate-canary/' /etc/caddy/Caddyfile"
        )
        with self.shell() as shell:
            draft = foundation.review(foundation.inspect(shell))
        self.assertFalse(draft.eligible)
        with self.subTest(boundary="application HTTP"):
            self.assertEqual(self.native("cat /var/lib/caddy/access-canary.log"), "")
        with self.subTest(boundary="module provisioning"):
            self.assertEqual(
                self.native("test ! -e /var/lib/caddy/validate-canary.log; printf '%s' $?"), "0"
            )
