"""Native WordPress maintenance support (docs/wordpress.md#maintaining-wordpress)."""

import shlex
from typing import override

from django.contrib.auth.models import Permission

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from discovery.fakes import run_worker
from operations.models import RemoteOperation

from . import execution
from .inspection_remote_testing import (
    CONTENT,
    IDENTIFIER_DB,
    InspectionServerCase,
    plugin_header,
)
from .install_apply_remote_testing import BASE
from .install_remote_testing import IDENTIFIER, NAME
from .maintenance_models import MaintenanceResult, Operation

Status = RemoteOperation.Status
Exit = execution.Exit
ROUTE = "barectl-route"
PLUGIN_ROUTE = "plugin-route"
ROUTES = (
    "<?php\n"
    "add_action('init', function () {\n"
    f"    add_rewrite_rule('^{ROUTE}/?$', 'index.php?barectl_route=1', 'top');\n"
    "});\n"
    "add_filter('query_vars', function ($vars) { $vars[] = 'barectl_route'; return $vars; });\n"
    "add_action('template_redirect', function () {\n"
    "    if (get_query_var('barectl_route')) {\n"
    "        header('Content-Type: text/plain'); echo 'barectl-route-ok'; exit;\n"
    "    }\n"
    "});\n"
)
PLUGIN = (
    plugin_header("Route plugin")
    + "add_action('init', function () {\n"
    + f"    add_rewrite_rule('^{PLUGIN_ROUTE}/?$', 'index.php?plugin_route=1', 'top');\n"
    + "});\n"
)
STALE = 'a:1:{s:12:"stale-marker";s:3:"new";}'
OPTIONS = (
    f"SELECT option_name, MD5(option_value) FROM {IDENTIFIER_DB}.wp_options "  # noqa: S608 - the test's own fixed name
    "WHERE option_name NOT LIKE '%transient%' AND option_name <> 'rewrite_rules' ORDER BY 1"
)


class MaintenanceServerCase(InspectionServerCase):
    """A disposable server on which Barectl installed WordPress through its own workflow."""

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.user.user_permissions.add(Permission.objects.get(codename="maintain_wordpress"))

    def sql(self, query: str) -> str:
        return self.administer(
            f"mariadb --no-defaults --protocol=socket -N -B {IDENTIFIER_DB} -e {shlex.quote(query)}"
        ).strip()

    def permalinks(self) -> None:
        """Pretty permalinks, so WordPress stores rewrite rules, and a stale stored set."""
        self.set_option("permalink_structure", "/%postname%/")
        self.set_option("rewrite_rules", STALE)

    def set_option(self, name: str, value: str) -> None:
        query = f"UPDATE wp_options SET option_value='{value}' WHERE option_name='{name}'"  # noqa: S608 - the test's own fixed names
        self.sql(query)

    def stored_rules(self) -> str:
        return self.sql("SELECT option_value FROM wp_options WHERE option_name='rewrite_rules'")

    def routes(self) -> None:
        self.put(f"{CONTENT}/mu-plugins/routes.php", ROUTES)
        self.addCleanup(self.remove, f"{CONTENT}/mu-plugins/routes.php")
        self.put(f"{CONTENT}/plugins/route-plugin/route-plugin.php", PLUGIN)
        self.addCleanup(self.remove, f"{CONTENT}/plugins/route-plugin")
        entry = "route-plugin/route-plugin.php"
        self.set_option("active_plugins", f'a:1:{{i:0;s:{len(entry)}:"{entry}";}}')
        self.addCleanup(self.set_option, "active_plugins", "a:0:{}")

    def page(self, path: str) -> tuple[str, str]:
        out = self.administer(
            f"curl -sk --max-time 20 --resolve {NAME}:443:127.0.0.1 -w '\\n%{{http_code}}' "
            f"https://{NAME}{path}; true"
        )
        body, _, status = out.rpartition("\n")
        return status.strip(), body

    def review_maintenance(self, operation: str = Operation.REWRITE) -> ConfigurationPlan:
        self.refresh()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/{IDENTIFIER}/wordpress/maintenance/prepare/",
            {"maintenance-operation": operation},
        )
        self.assertEqual(response.status_code, 302, response.content[:300])
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def eligible_maintenance(self, operation: str = Operation.REWRITE) -> ConfigurationPlan:
        plan = self.review_maintenance(operation)
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def run_maintenance(
        self, operation: str = Operation.REWRITE, plan: ConfigurationPlan | None = None
    ) -> ApplyRun:
        run = self.request(plan or self.eligible_maintenance(operation))
        run_worker()
        run.refresh_from_db()
        return run

    def assert_maintained(self, run: ApplyRun) -> MaintenanceResult:
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            f"{run.failure}\n{self.journal_tail(run)}",
        )
        return MaintenanceResult.objects.get(run=run)

    def nginx(self) -> str:
        """Every byte of Nginx's configuration and the backups Barectl keeps of it."""
        return self.administer(
            "find /etc/nginx /var/backups/nginx -xdev -type f -exec sha256sum -- {} + | sort; "
            "find /etc/nginx -xdev -printf '%y %m %U %G %p %l\\n' | sort; nginx -T 2>&1 | sha256sum"
        )

    def assert_same(self, before: dict[str, str], after: dict[str, str]) -> None:
        for name in before:
            self.assertEqual(after[name].splitlines(), before[name].splitlines(), name)

    def snapshot(self) -> dict[str, str]:
        """What a maintenance run must leave exactly as it was."""
        before = self.tree()
        before["options"] = self.administer(
            f"mariadb --no-defaults --protocol=socket -N -B -e {shlex.quote(OPTIONS)}"
        )
        before["nginx"] = self.nginx()
        # A directory's modification time moves with the run's own staging directory.
        before["files"] = self.administer(
            f"find {BASE} -xdev -not -path '{BASE}/.wp-*' -type f "
            "-printf '%y %m %U %G %s %T@ %p\\n' "
            f"| sort; find {BASE} -xdev -not -path '{BASE}/.wp-*' -not -type f "
            "-printf '%y %m %U %G %p\\n' | sort"
        )
        before.pop("public")
        before.pop("base")
        return before
