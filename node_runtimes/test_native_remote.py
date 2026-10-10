"""Signed Node installs and scoped native pins (docs/node-runtimes-native-design.md)."""

import shlex
from typing import override
from unittest.mock import patch

from django.contrib.auth.models import Permission

from bootstrap import native as execution
from bootstrap.actions import BOOTSTRAP
from bootstrap.apply_remote_testing import ApplyAcceptanceTestCase
from bootstrap.models import ConfigurationPlan, Execution, Verification
from discovery import ssh
from discovery.fakes import run_worker
from operations.models import RemoteOperation
from sites.native_testing import create_site, remove_site

from . import alternatives, catalog, npm_tree, runtime
from .changes import request_runtime_change
from .services import request_runtime_preparation

PURGE = (
    "update-alternatives --remove-all node 2>/dev/null; "
    "rm -rf /etc/mise /usr/local/lib/mise /usr/local/share/mise; true"
)


class NativeRuntimeTests(ApplyAcceptanceTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.user.user_permissions.add(
            *Permission.objects.filter(
                content_type__app_label="sites",
                codename__in=("view_siteplan", "prepare_siteplan", "apply_siteplan"),
            )
        )
        self.administer(PURGE)
        self.addCleanup(self.administer, PURGE)
        self.administer("DEBIAN_FRONTEND=noninteractive apt-get -q -y install gpg curl >/dev/null")

    def node_plan(self, version: str, identifier: str = "") -> ConfigurationPlan:
        preparation = request_runtime_preparation(
            self.server, self.user, version, identifier=identifier
        )
        self.assertIsNotNone(preparation)
        run_worker()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def select(self, version: str, identifier: str = "") -> None:
        run = self.apply(self.node_plan(version, identifier))
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (RemoteOperation.Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure + self.journal(run.unit_name),
        )

    def test_signed_install_reconstructs_default_and_preserves_existing_site_pins(self) -> None:
        self.select(catalog.DEFAULT)
        self.assertEqual(self.administer("node --version").strip(), "v24.21.0")
        self.assertEqual(self.administer("npm --version").strip(), "11.19.0")
        self.assertEqual(self.administer("npx --version").strip(), "11.19.0")
        release = self.administer('. /etc/os-release; printf %s "$VERSION_ID"')
        php = {"24.04": "8.3", "26.04": "8.5"}[release]
        self.administer(create_site("shop", ("shop.example.com",), php))
        self.addCleanup(self.administer, remove_site("shop", php))
        self.administer("printf 'application bytes' >/var/www/shop/public/content-marker")
        self.select("22.23.3", "shop")
        self.assertEqual(self.administer("cd /var/www/shop && node --version").strip(), "v24.21.0")
        self.assertEqual(
            self.administer(f"{catalog.executable('22.23.3')} --version").strip(), "v22.23.3"
        )
        pin = self.administer("sha256sum /var/www/shop/.node-version").strip()
        self.select("22.23.3")
        self.assertEqual(self.administer("node --version").strip(), "v22.23.3")
        self.assertEqual(self.administer("npm --version").strip(), "10.9.9")
        self.assertEqual(self.administer("npx --version").strip(), "10.9.9")
        self.assertEqual(self.administer("sha256sum /var/www/shop/.node-version").strip(), pin)
        self.assertEqual(
            self.administer("cat /var/www/shop/public/content-marker"), "application bytes"
        )
        with ssh.connect_alias("disposable") as shell:
            observed = runtime.observe_runtime(shell)
        self.assertEqual(observed.failure, "")
        self.assertIsNotNone(observed.inventory)
        if observed.inventory is not None:
            self.assertEqual(observed.inventory.default, "22.23.3")
            self.assertEqual(set(observed.inventory.installed), set(catalog.VERSIONS))
            self.assertEqual(observed.inventory.sites, {"shop": "22.23.3"})
        self.assertTrue(self.node_plan("22.23.3", "shop").no_changes)

    def test_one_operator_intent_prepares_and_applies_prerequisites_and_runtime(self) -> None:
        change = request_runtime_change(self.server, self.user.pk, catalog.DEFAULT)
        self.assertIsNotNone(change)
        run_worker()
        if change is None:
            self.fail("The runtime intent was not queued.")
        change.refresh_from_db()
        self.assertEqual(change.status, "succeeded", change.failure)
        self.assertEqual(
            list(change.steps.order_by("position").values_list("preparation__action", flat=True)),
            ["metadata_refresh", "php_source_tools", "node_runtime"],
        )
        self.assertEqual(
            self.administer(f"{catalog.executable(catalog.DEFAULT)} --version").strip(),
            "v" + catalog.DEFAULT,
        )

    def test_missing_signature_refuses_before_tool_or_runtime_publication(self) -> None:
        with patch.object(catalog, "SIGNATURE_NAME", "missing-signature.asc"):
            run = self.apply(self.node_plan(catalog.DEFAULT))
        self.assertEqual(
            (run.status, run.execution, run.exit_status),
            (RemoteOperation.Status.FAILED, Execution.TOOL_REFUSED, 32),
            run.failure + self.journal(run.unit_name),
        )
        self.assertEqual(
            self.administer("ls -d /usr/local/lib/mise /etc/mise 2>/dev/null; true"), ""
        )

    def test_reviewed_native_drift_refuses_before_downloading(self) -> None:
        plan = self.node_plan(catalog.DEFAULT)
        self.administer("install -d -o root -g root -m 0755 /etc/mise")
        self.administer("printf 'foreign config' >/etc/mise/config.toml")
        run = self.apply(plan)
        self.assertEqual(run.execution, Execution.DRIFT, run.failure + self.journal(run.unit_name))
        self.assertNotIn("gpgv", self.journal(run.unit_name))
        self.assertEqual(self.administer("cat /etc/mise/config.toml"), "foreign config")

    def test_unrecognized_native_site_pin_never_becomes_observed_inventory(self) -> None:
        self.administer(
            "install -d -o root -g root -m 0755 /var/www/orphan; "
            "printf '24.21.0\\n' >/var/www/orphan/.node-version; "
            "chmod 0644 /var/www/orphan/.node-version"
        )
        self.addCleanup(self.administer, "rm -rf /var/www/orphan")
        with ssh.connect_alias("disposable") as shell:
            observed = runtime.observe_runtime(shell)
        self.assertIsNone(observed.inventory)
        self.assertNotEqual(observed.failure, "")

    def test_foreign_npm_link_refuses_without_replacing_it(self) -> None:
        self.administer("ln -s /bin/true /usr/local/bin/npm")
        self.addCleanup(self.administer, "rm -f /usr/local/bin/npm")
        preparation = request_runtime_preparation(self.server, self.user, catalog.DEFAULT)
        run_worker()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertFalse(plan.eligible)
        self.assertEqual(self.administer("readlink /usr/local/bin/npm").strip(), "/bin/true")
        self.assertEqual(self.administer("test -e /etc/mise/config.toml; echo $?").strip(), "1")

    def test_modified_bundled_npm_is_never_executed_or_accepted_from_cache(self) -> None:
        self.select(catalog.DEFAULT)
        cli = (
            catalog.executable(catalog.DEFAULT).rsplit("/bin/", 1)[0]
            + "/lib/node_modules/npm/bin/npm-cli.js"
        )
        self.administer(f"printf 'foreign npm bytes' >{cli}")
        with ssh.connect_alias("disposable") as shell:
            observed = runtime.observe_runtime(shell)
        self.assertIsNone(observed.inventory)
        preparation = request_runtime_preparation(self.server, self.user, "22.23.3")
        run_worker()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertFalse(plan.eligible)

        self.assertEqual(self.administer(f"cat {cli}"), "foreign npm bytes")

    def test_revoked_site_authority_cannot_submit_a_prepared_pin(self) -> None:
        release = self.administer('. /etc/os-release; printf %s "$VERSION_ID"')
        php = {"24.04": "8.3", "26.04": "8.5"}[release]
        self.administer(create_site("shop", ("shop.example.com",), php))
        self.addCleanup(self.administer, remove_site("shop", php))
        plan = self.node_plan(catalog.DEFAULT, "shop")
        run = self.request(plan)
        self.user.is_superuser = False
        self.user.save(update_fields=["is_superuser"])
        self.user.user_permissions.remove(
            Permission.objects.get(content_type__app_label="sites", codename="apply_siteplan")
        )
        for permission in {*BOOTSTRAP.prepare, *BOOTSTRAP.apply}:
            app, codename = permission.split(".")
            self.user.user_permissions.add(
                Permission.objects.get(content_type__app_label=app, codename=codename)
            )
        run_worker()
        run.refresh_from_db()
        self.assertEqual(
            (run.status, run.execution, run.dispatched_at),
            (RemoteOperation.Status.FAILED, Execution.NOT_SUBMITTED, None),
            run.failure,
        )
        self.assertIn("permission", run.failure)
        self.assertEqual(
            self.administer(
                "test ! -e /var/www/shop/.node-version && "
                "test ! -e /etc/mise/config.toml && echo unchanged"
            ).strip(),
            "unchanged",
        )
        self.assertNotIn(run.unit_name, self.units())

    def test_another_controller_lock_refuses_before_runtime_publication(self) -> None:
        plan = self.node_plan(catalog.DEFAULT)
        holder = self.submit(
            lambda unit, boot, deadline: "; ".join(
                [*execution.admission(unit, boot, deadline), "sleep 120"]
            ),
            alias="disposable-second",
        )
        self.addCleanup(self.administer, f"systemctl kill --signal=SIGKILL {holder}; true")
        self.administer(
            "for i in $(seq 1 100); do "
            f"if ! flock -n {execution.LOCK_FILE} true; then exit 0; fi; "
            "sleep 0.05; done; exit 1"
        )
        run = self.apply(plan)
        self.assertEqual(run.execution, Execution.LOCK_CONFLICT, run.failure)
        self.assertEqual(self.inspect(holder).execution, Execution.RUNNING)
        self.assertEqual(
            self.administer("test ! -e /etc/mise/config.toml && echo unchanged").strip(),
            "unchanged",
        )
        self.assertEqual(
            self.administer("test ! -e /usr/local/share/mise && echo absent").strip(),
            "absent",
        )
        self.assertNotIn("gpgv", self.journal(run.unit_name))

    def test_passive_python_reads_ignore_hostile_working_directory_and_environment(self) -> None:
        fixture = self.administer("mktemp -d /tmp/barectl-node-hostile.XXXXXX").strip()
        self.assertRegex(fixture, r"^/tmp/barectl-node-hostile\.[A-Za-z0-9]{6}$")
        self.addCleanup(self.administer, f"rm -rf {fixture}")
        injected = f"open('{fixture}/executed','w').write('unexpected'); raise RuntimeError"
        self.administer(
            f"install -d -m 0777 {fixture}; "
            f"for p in json hashlib subprocess; do printf %s {shlex.quote(injected)} "
            f">{fixture}/$p.py; done"
        )
        for command in (alternatives.inspect_command(), npm_tree.command(verify=True)):
            with self.subTest(command=command.split(" -c", 1)[0]):
                unsafe = command.replace("/usr/bin/python3 -I -c", "/usr/bin/python3 -c")
                self.administer(
                    f"cd {fixture}; export PYTHONPATH={fixture}; selected=''; "
                    f"( {unsafe} ) >/dev/null 2>&1 || true"
                )
                self.assertEqual(
                    self.administer(f"test -f {fixture}/executed && echo executed").strip(),
                    "executed",
                )
                self.administer(f"rm {fixture}/executed")
                self.administer(
                    f"cd {fixture}; export PYTHONPATH={fixture}; selected=''; " + command
                )
                self.assertEqual(
                    self.administer(f"test ! -e {fixture}/executed && echo absent").strip(),
                    "absent",
                )
