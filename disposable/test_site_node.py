"""A site's Node selection changes only its own native command links."""

import shlex

from django.test import tag

from operations import engine
from operations.inputs import PreparationInputs
from runtimes.change import ADD_RUNTIME
from sites.change import CREATE_SITE

from .change_testing import apply_change
from .runtime_defaults_testing import DefaultChangeCase
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class SiteNodeSelection(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s7node"
    records: tuple[str, ...] = ("site-node-26.04", "site-node-interrupted-26.04")

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
        from sites import node_change
        from sites.configuration import SiteSettings, render_pool

        inputs = PreparationInputs("nodejs_24", "s7node")
        with self.shell() as shell:
            evidence = node_change.inspect(shell, inputs)
            engine._sites_digest(shell, node_change.review(evidence, inputs))
            self.checkpoint("site-node-26.04", shell)
        duplicate = render_pool(SiteSettings("s7node", ("s7node.example.com",), "php85"))
        self.native(
            "printf %s "
            + shlex.quote(duplicate)
            + " >/etc/php-fpm/php85/pools/s7node.conf; systemctl reload php-fpm@php85.service"
        )
        try:
            with self.shell() as fresh:
                evidence = node_change.inspect(fresh, inputs)
                draft = node_change.review(evidence, inputs)
                self.assertFalse(draft.eligible)
                self.assertIn("two masters", " ".join(draft.refusals))
                if evidence.state is None:
                    self.fail("Interrupted native state disappeared.")
                matches = [
                    site
                    for site in evidence.state["native"]["sites"]
                    if site["identifier"] == "s7node"
                ]
                self.assertEqual(len(matches), 1)
                engine._sites_digest(fresh, draft)
                self.checkpoint("site-node-interrupted-26.04", fresh)
        finally:
            self.native(
                "rm /etc/php-fpm/php85/pools/s7node.conf; systemctl reload php-fpm@php85.service"
            )


@tag(SCENARIO_TAG)
class SiteNodeValidators(DefaultChangeCase):
    layer = "L1"
    exclusive = True
    validator = True
    prefix = "s7nodevalidate"

    def test_post_review_foreign_command_refuses_before_creating_other_node_links(self) -> None:
        from sites.node_change import SET_SITE_NODE

        apply_change(self, ADD_RUNTIME, PreparationInputs("nodejs_24"))
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs("php84", "s7nodevalidate", ("s7nodevalidate.example.com",)),
        )
        result, _ = self.apply_change(
            SET_SITE_NODE,
            PreparationInputs("nodejs_24", "s7nodevalidate"),
            before_submit=(
                "printf administrator-command >/var/www/s7nodevalidate/bin/npx; "
                "chmod 755 /var/www/s7nodevalidate/bin/npx"
            ),
        )
        self.assertEqual((result.result_class, result.reason), ("refused", "precondition"))
        self.assertEqual(
            self.native("cat /var/www/s7nodevalidate/bin/npx"), "administrator-command"
        )
        self.native(
            "test ! -e /var/www/s7nodevalidate/bin/node; test ! -e /var/www/s7nodevalidate/bin/npm"
        )
