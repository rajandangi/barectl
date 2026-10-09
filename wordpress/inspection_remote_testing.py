"""A disposable server on which Barectl installed WordPress through its own workflow, for the
inspection and maintenance suites (docs/wordpress.md#inspecting-wordpress).

See ``bootstrap/test_apply_remote.py`` for the contract.
"""

import json
import shlex
from typing import override

from django.contrib.auth.models import Permission

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from discovery.fakes import run_worker
from discovery.services import request_discovery
from operations.models import RemoteOperation

from . import execution
from .inspection_models import (
    InspectionItem,
    InspectionResult,
    Operation,
)
from .install_apply_remote_testing import BASE, SITE_FILE, USER, InstallApplyTestCase
from .install_remote_testing import IDENTIFIER, PRIVATE, PUBLIC

Status = RemoteOperation.Status
Exit = execution.Exit


CONTENT = f"{PUBLIC}/wp-content"
MARKER = "/var/tmp/barectl-inspection-marker"  # noqa: S108 - a file in the disposable server
ENVIRONMENT = {
    "HOME",
    "LC_ALL",
    "PATH",
    "PWD",
    "TMPDIR",
    "WP_CLI_CACHE_DIR",
    "WP_CLI_CONFIG_PATH",
    "WP_CLI_DISABLE_AUTO_CHECK_UPDATE",
    "WP_CLI_PACKAGES_DIR",
}
# A must-use plugin that records who ran it and with which environment.
RECORDER = (
    "<?php\n"
    f"file_put_contents('{MARKER}', json_encode(['uid' => posix_geteuid(), "
    "'env' => array_keys(getenv()), 'cwd' => getcwd()]) . \"\\n\", FILE_APPEND);\n"
)
HOSTILE = (
    "<?php\n"
    'echo "debug: secret=hunter2\\n";\n'
    'fwrite(STDERR, "stderr: secret=hunter2\\n");\n'
    "trigger_error('notice: secret=hunter2', E_USER_WARNING);\n"
    "var_dump(['password' => 'hunter2']);\n"
)


def plugin_header(name: str, version: str = "1.0") -> str:
    return f"<?php\n/*\nPlugin Name: {name}\nVersion: {version}\n*/\n"


class InspectionServerCase(InstallApplyTestCase):
    """A disposable server on which Barectl installed WordPress through its own workflow."""

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        for codename in ("inspect_wordpress", "view_siteapplicationobservation"):
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        super().setUp()
        run = self.apply_install(self.eligible())
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            f"{run.failure}\n{self.journal_tail(run)}",
        )
        self.refresh()

    def refresh(self) -> None:
        """Observe the server again, as an operator's connection check does."""
        request_discovery(self.server)
        run_worker()

    def put(self, path: str, text: str, mode: str = "644", owner: str = USER) -> None:
        directory = path.rsplit("/", 1)[0]
        self.administer(
            f"install -d -o {owner} -g {owner} -m 755 {directory} && "
            f"printf %s {shlex.quote(text)} >{path} && chown {owner}:{owner} {path} && "
            f"chmod {mode} {path}"
        )

    def remove(self, path: str) -> None:
        self.administer(f"rm -rf {path}")

    def plugin(self, slug: str, version: str = "1.0") -> None:
        self.put(f"{CONTENT}/plugins/{slug}/{slug}.php", plugin_header(slug, version))
        self.addCleanup(self.remove, f"{CONTENT}/plugins/{slug}")

    def recorder(self) -> None:
        self.put(f"{CONTENT}/mu-plugins/recorder.php", RECORDER)
        self.administer(f"rm -f {MARKER}")
        self.addCleanup(self.administer, f"rm -f {MARKER} {CONTENT}/mu-plugins/recorder.php")

    def marked(self) -> list[dict[str, object]]:
        text = self.administer(f"cat {MARKER} 2>/dev/null; true")
        marks = [json.loads(line) for line in text.splitlines()]
        # Web requests the pool served run the recorder too; only inspections are of interest.
        return [mark for mark in marks if str(mark["cwd"]).startswith(f"{BASE}/.wp-")]

    def block(self, host: str) -> None:
        """Make a catalog host unreachable by a local name that serves a certificate WP-CLI
        refuses."""
        self.administer(f"echo '127.0.0.1 {host}' >>/etc/hosts")
        self.addCleanup(
            self.administer,
            f"grep -v ' {host}$' /etc/hosts >/tmp/hosts.new; cat /tmp/hosts.new >/etc/hosts; "
            "rm -f /tmp/hosts.new",
        )

    def review_inspection(self, operation: str = Operation.INSPECT) -> ConfigurationPlan:
        self.refresh()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/{IDENTIFIER}/wordpress/inspection/prepare/",
            {"inspection-operation": operation},
        )
        self.assertEqual(response.status_code, 302, response.content[:300])
        run_worker()
        from bootstrap.models import PlanPreparation

        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def eligible_inspection(self, operation: str = Operation.INSPECT) -> ConfigurationPlan:
        plan = self.review_inspection(operation)
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def run_inspection(
        self, operation: str = Operation.INSPECT, plan: ConfigurationPlan | None = None
    ) -> ApplyRun:
        run = self.request(plan or self.eligible_inspection(operation))
        run_worker()
        run.refresh_from_db()
        return run

    def assert_inspected(self, run: ApplyRun) -> InspectionResult:
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            f"{run.failure}\n{self.journal_tail(run)}",
        )
        return InspectionResult.objects.get(run=run)

    def names(self, result: InspectionResult, kind: str) -> list[str]:
        return list(
            InspectionItem.objects.filter(result=result, kind=kind).values_list("name", flat=True)
        )

    def residue(self) -> str:
        return self.administer(f"ls -A {BASE} | grep '^[.]wp' || true").strip()

    def options_command(self) -> str:
        return f"mariadb --no-defaults --protocol=socket -N -B -e {shlex.quote(OPTIONS)}"

    def tree(self) -> dict[str, str]:
        """Everything an inspection must leave exactly as it was."""
        reads = {
            "public": f"find {PUBLIC} -xdev -printf '%y %m %U %G %s %T@ %p\\n' | sort | sha256sum",
            "base": f"find {BASE} -maxdepth 1 -printf '%y %m %U %G %p\\n' | sort",
            "private": f"sha256sum {PRIVATE}/wp-config.php",
            "site": f"sha256sum {SITE_FILE}",
            "tables": self.tables_command(),
            "options": self.options_command(),
            "backups": "ls -A /var/backups/nginx",
        }
        return {name: self.administer(command) for name, command in reads.items()}

    def assert_unchanged(self, before: dict[str, str]) -> None:
        after = self.tree()
        self.assertEqual(
            {name: text.splitlines() for name, text in after.items()},
            {name: text.splitlines() for name, text in before.items()},
        )


IDENTIFIER_DB = f"s{IDENTIFIER}"
# WordPress writes its own transients and caches whenever it loads, so they are not Barectl's.
OPTIONS = (
    f"SELECT option_name, MD5(option_value) FROM {IDENTIFIER_DB}.wp_options "  # noqa: S608 - the test's own fixed name
    "WHERE option_name NOT LIKE '%transient%' ORDER BY 1"
)
