"""A site's Node selection changes only its own native command links."""

import shlex

from django.test import tag

from operations.inputs import PreparationInputs
from runtimes.change import ADD_RUNTIME
from sites.change import CREATE_SITE

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class SiteNodeSelection(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s7node"

    def test_node_selection_reconstructs_and_leaves_php_and_site_content_unchanged(self) -> None:
        from sites.node_change import SET_SITE_NODE

        for entry in ("nodejs_22", "nodejs_24"):
            apply_change(self, ADD_RUNTIME, PreparationInputs(entry))
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs("php84", "s7node", ("s7node.example.com",)),
        )
        command = (
            "sha256sum /etc/caddy/sites/s7node.caddy /etc/php-fpm/php84/pools/s7node.conf "
            "/var/www/s7node/current/public/index.php /var/www/s7node/bin/php "
            "/var/www/s7node/bin/composer /var/www/s7node/bin/wp; "
            "stat -c '%i %u %g %a' /run/php-fpm/php84/s7node.sock; "
            "systemctl show php-fpm@php84.service php-fpm@php85.service -p MainPID -p InvocationID"
        )
        before = self.native(command)
        for entry, major in (("nodejs_24", "24"), ("nodejs_22", "22")):
            apply_change(self, SET_SITE_NODE, PreparationInputs(entry, "s7node"))
            self.assertEqual(self.native(command), before)
            self.assertEqual(
                self.native(
                    shlex.join(
                        ["/var/www/s7node/bin/node", "-p", "process.versions.node.split('.')[0]"]
                    )
                ).strip(),
                major,
            )
            for name in ("node", "npm", "npx"):
                self.assertEqual(
                    self.native("readlink " + shlex.quote("/var/www/s7node/bin/" + name)).strip(),
                    f"/nix/var/nix/profiles/barectl/{entry}/bin/{name}",
                )
            from discovery.observations import collect

            with self.shell() as fresh:
                sites = collect(fresh).sites.value
                site = next(site for site in sites if site.identifier == "s7node")
                self.assertEqual(site.node_runtime, entry)
