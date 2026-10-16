"""S9 adopts supported hand edits and scopes an unsupported one to its site."""

import shlex
from typing import TypedDict

from django.test import tag

from discovery.observations import collect

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


class _Observed(TypedDict):
    state: str
    missing: list[str]


@tag(SCENARIO_TAG)
class JudgeByShape(ScenarioTestCase):
    """Three sites: supported hand edits are adopted, an unsupported one is scoped."""

    layer = "L1"
    exclusive = True
    prefix = "s9"

    def test_supported_hand_edits_are_adopted_and_one_unsupported_edit_is_scoped(self) -> None:
        from operations.inputs import PreparationInputs
        from sites import change, php_change

        for suffix in ("alpha", "beta"):
            identifier = self.prefix + suffix
            apply_change(
                self,
                change.CREATE_SITE,
                PreparationInputs("php84", identifier, (identifier + ".example.com",)),
            )
        self.create_gamma_by_hand()

        alpha = self.prefix + "alpha"
        pool = f"/etc/php-fpm/sites/{alpha}/php84/pools/{alpha}.conf"
        self.native(
            "printf %s "
            + shlex.quote(
                "\nrequest_terminate_timeout = 60s\nphp_admin_value[memory_limit] = 256M\n"
            )
            + " >>"
            + pool
            + "; systemctl restart php-fpm-site-php84@"
            + alpha
            + ".service"
        )
        self.native(
            "printf %s "
            + shlex.quote("\n# An operator's note, ignored by the Caddy adapter.\n")
            + " >>/etc/caddy/sites/"
            + alpha
            + ".caddy; "
            "/nix/var/nix/profiles/barectl/caddy/bin/caddy reload --config /etc/caddy/Caddyfile "
            "--adapter caddyfile --address unix//run/caddy/admin.sock"
        )

        sites = self.observed()
        for suffix in ("alpha", "gamma"):
            identifier = self.prefix + suffix
            self.assertEqual(sites[identifier]["state"], "managed", sites[identifier])
        inputs = PreparationInputs("php84", alpha, (alpha + ".example.com",))
        with self.shell() as shell:
            adopted = change.review(change.inspect(shell, inputs), inputs)
            self.assertTrue(adopted.eligible, adopted.refusals)
            self.assertTrue(adopted.no_changes, adopted.document)

        beta = self.prefix + "beta"
        beta_pool = f"/etc/php-fpm/sites/{beta}/php84/pools/{beta}.conf"
        self.native(
            "printf %s "
            + shlex.quote("\nphp_admin_value[max_execution_time] = 45\n")
            + " >>"
            + beta_pool
            + "; systemctl restart php-fpm-site-php84@"
            + beta
            + ".service"
        )
        sites = self.observed()
        self.assertEqual(sites[beta]["state"], "not_following", sites[beta])
        self.assertEqual(len(sites[beta]["missing"]), 1, sites[beta])
        self.assertIn("pool", " ".join(sites[beta]["missing"]))
        for suffix in ("alpha", "gamma"):
            identifier = self.prefix + suffix
            self.assertEqual(sites[identifier]["state"], "managed", sites[identifier])
        blocked = PreparationInputs("php85", beta)
        with self.shell() as shell:
            refused = php_change.review(php_change.inspect(shell, blocked), blocked)
            self.assertFalse(refused.eligible)
            allowed = PreparationInputs("php85", alpha)
            permitted = php_change.review(php_change.inspect(shell, allowed), allowed)
            self.assertTrue(permitted.eligible, permitted.refusals)

    def create_gamma_by_hand(self) -> None:
        """Make the convention site with ordinary native operations, outside the engine."""
        from sites import observation

        identifier = self.prefix + "gamma"
        source = (
            observation.COMMON_SOURCE
            + "\n"
            + f"settings = setting({identifier!r}, [{identifier + '.example.com'!r}], 'php84')\n"
            + "identity = free_identity()\n"
            + "proxy = free_identity((identity,))\n"
            + "account = create_account(settings, identity)\n"
            + "lock = create_layout(settings)\n"
            + "configure_pool(settings, account, proxy)\n"
            + f"publish_caddy({identifier!r}, caddy_file(settings), None)\n"
            + "os.close(lock)\n"
        )
        self.native(observation.python_command(source, ()))

    def observed(self) -> dict[str, _Observed]:
        with self.shell() as shell:
            rows = collect(shell).sites.value
        return {
            row.identifier: {"state": str(row.state), "missing": list(row.missing)} for row in rows
        }
