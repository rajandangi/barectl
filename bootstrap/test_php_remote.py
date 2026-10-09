"""Exact reviewed PHP FPM and CLI installation on a real, disposable Ubuntu server.

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The tests reuse the engine Nginx qualified
in ``bootstrap/test_package_remote.py``; they establish what is specific to the PHP
profile or to two profiles on one server: the installation itself with an epoch in a
dependency's version, verification of the pool's socket and the CLI, the partial and
satisfied baselines, the service effects, the refusals of other releases, customized or
additional pools and conflicting socket listeners, drift and guard refusals, privilege,
a lost connection, a fresh controller, and Nginx and PHP runs racing from two
controllers. Every run goes through actual APT, dpkg, debconf and systemd; ground truth
is read through ``docker exec``. Tests that need PHP absent purge it first and restore
the provisioned PHP from APT's package cache afterwards. The PHP version is the default of
the server's release, such as 8.3 on Ubuntu 24.04.
"""

import json
import re
import shlex
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from dashboard.testing import TEST_MANIFEST
from discovery import ssh
from discovery.fakes import run_worker
from discovery.models import ComponentObservation, DiscoveryAttempt
from discovery.native_testing import setting
from discovery.services import request_discovery
from discovery.ssh import CommandResult, RemoteShell
from operations.models import RemoteOperation
from servers.ssh_config import ConnectionTarget

from . import native
from .apply_remote_testing import is_inspection
from .models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
    Verification,
)
from .native_testing import PHP, PHP_CLI, PHP_FPM, RELEASE, REMOVE_NGINX, RESTORE_NGINX
from .test_coordination_remote import ControllerTestCase

Status = RemoteOperation.Status
Effect = PlanEffect.Kind
Reason = PlanRefusal.Reason
# The release's PHP version, such as "8.3", and its configuration directory.
VERSION = RELEASE.php
ETC = f"/etc/php/{VERSION}"
PHP_PACKAGES = " ".join(name for name in PHP.packages if name != "needrestart")
REMOVE_PHP = (
    f"systemctl stop {PHP_FPM} 2>/dev/null; set -e; "
    f"DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq {PHP_PACKAGES} >/dev/null"
)
# Put the provisioned PHP back from APT's cache, whatever a test left: other releases'
# directories, extra pools, masks, holds and listeners, and the marks it had.
RESTORE_PHP = (
    "pkill -f '[b]arectl-test-socket'; rm -rf /etc/php/8.2; "
    f"systemctl unmask {PHP_FPM} >/dev/null 2>&1; apt-mark unhold {PHP_FPM} >/dev/null; "
    f"set -e; DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq {PHP_PACKAGES} >/dev/null; "
    f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download {PHP_FPM} >/dev/null; "
    f"systemctl enable -q {PHP_FPM}; systemctl restart {PHP_FPM}"
)
# What must not change when a run stops before dpkg.
PACKAGE_STATE = (
    "sha256sum /var/lib/dpkg/status /var/lib/apt/extended_states | cut -d' ' -f1; "
    "wc -l </var/log/dpkg.log"
)
# The PHP version each release shipped in its release pocket, older than the updates
# pocket's candidate.
OLDER = {"24.04": "8.3.6-0maysync1", "26.04": "8.5.4-0ubuntu1"}[RELEASE.version]
# A process holding the default pool's socket path, as another service would.
SOCKET_HOLDER = (
    "import socket, time; s = socket.socket(socket.AF_UNIX); "
    f"s.bind('{PHP.socket}'); s.listen(); time.sleep(300)"
)
# A new, independent controller in its own process and database: it registers the server
# through the second alias and key, discovers it, and reviews the PHP profile.
RECONSTRUCTION = """
import json
import os
import sys
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest = sys.argv[1:]
configured.DATABASES["default"]["NAME"] = database
configured.SSH_CONFIG_PATH = ssh_config
configured.VITE_MANIFEST_PATH = Path(manifest)
configured.VITE_DEV_SERVER_URL = ""
configured.ALLOWED_HOSTS = ["testserver"]

import django

django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client

from bootstrap.models import ConfigurationPlan
from discovery.fakes import run_worker
from discovery.models import ComponentObservation
from discovery.services import request_discovery
from servers.models import Server

call_command("migrate", verbosity=0)
user = get_user_model().objects.create_user("fresh-operator")
for codename in ("view_server", "view_configurationplan", "prepare_configurationplan"):
    user.user_permissions.add(Permission.objects.get(codename=codename))
server = Server.objects.create(name="Reconstructed", ssh_alias="disposable-second")
request_discovery(server)
run_worker()
php = ComponentObservation.objects.get(component="php-fpm")
client = Client()
client.force_login(user)
client.post(f"/servers/{server.pk}/plans/prepare/", {"action": "php"}, secure=True)
run_worker()
plan = ConfigurationPlan.objects.get()
print(json.dumps({
    "packages": php.packages.splitlines(),
    "units": [f"{u.name} {u.active_state} {u.unit_file_state}" for u in php.service_units.all()],
    "no_changes": plan.no_changes,
    "eligible": plan.eligible,
}))
"""


@dataclass(frozen=True)
class Reconstructed:
    """What the independent controller observed and reviewed."""

    packages: list[str]
    units: list[str]
    no_changes: bool
    eligible: bool


class _RecordingShell:
    def __init__(self, shell: RemoteShell, commands: list[str]) -> None:
        self.shell = shell
        self.commands = commands

    @property
    def host_key(self) -> str:
        return self.shell.host_key

    def run(self, command: str) -> CommandResult:
        self.commands.append(command)
        return self.shell.run(command)


class PhpAcceptanceTestCase(ControllerTestCase):
    """The disposable server, restored to its provisioned PHP afterwards."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.user.user_permissions.add(Permission.objects.get(codename="add_discoveryattempt"))
        self.addCleanup(self.administer, RESTORE_PHP)

    def remove_php(self) -> None:
        self.administer(REMOVE_PHP)
        self.logged = int(self.administer("wc -l </var/log/dpkg.log"))

    def php_plan(self) -> ConfigurationPlan:
        plan = self.plan("php")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def status(self, *names: str) -> dict[str, str]:
        """Each named package's version and dpkg state, read natively."""
        shown = self.administer(
            f"dpkg-query -W -f='${{Package}} ${{Version}} ${{db:Status-Abbrev}}\\n' "
            f"{' '.join(names)} 2>/dev/null; true"
        )
        return {line.split()[0]: " ".join(line.split()[1:]) for line in shown.splitlines() if line}

    def installed(self, name: str) -> bool:
        return self.status(name).get(name, "").endswith(" ii")

    def assert_php_not_installed(self) -> None:
        self.assertFalse(self.installed(PHP_FPM))
        since = self.administer(f"tail -n +{self.logged + 1} /var/log/dpkg.log")
        self.assertNotRegex(since, rf" (install|configure) {re.escape(PHP_FPM)}:")

    def assert_serving(self) -> None:
        """The distribution's pool runs, enabled, on its socket, and the CLI reports the
        release's PHP version."""
        self.assertEqual(
            self.administer(
                f"systemctl is-enabled {PHP_FPM}; systemctl is-active {PHP_FPM}"
            ).split(),
            ["enabled", "active"],
        )
        self.assertIn(PHP.socket or "", self.administer(f"ss -Hlx src {PHP.socket}"))
        self.assertRegex(
            self.administer(f"php{VERSION} -v"), rf"\APHP {re.escape(VERSION)}\.\d+ \(cli\) "
        )

    @contextmanager
    def recording(self) -> Iterator[list[str]]:
        """Record every command Barectl's connections run."""
        commands: list[str] = []
        real = ssh.connect

        @contextmanager
        def connect(target: ConnectionTarget) -> Iterator[RemoteShell]:
            with real(target) as shell:
                yield _RecordingShell(shell, commands)

        with mock.patch.object(ssh, "connect", connect):
            yield commands


class PhpInstallationTests(PhpAcceptanceTestCase):
    def test_a_fresh_installation_survives_a_lost_connection_and_is_reconstructed(self) -> None:
        # Neither Nginx nor PHP is installed: PHP needs no web server.
        self.administer(REMOVE_NGINX)
        self.addCleanup(self.administer, RESTORE_NGINX)
        self.remove_php()
        automatic_before = set(self.administer("apt-mark showauto").split())
        plan = self.php_plan()
        installs = dict(
            plan.transitions.filter(step=PackageTransition.Step.INSTALL).values_list(
                "package", "version"
            )
        )
        self.assertEqual(installs["php-common"][:2], "2:")
        self.assertFalse([name for name in installs if "nginx" in name or "apache" in name])
        self.assertEqual(
            list(plan.roots.values_list("name", "installed")),
            [(PHP_FPM, False), (PHP_CLI, False)],
        )
        effects = list(plan.effects.values_list("kind", flat=True))
        self.assertIn(Effect.LOCAL_SOCKET, effects)
        self.assertNotIn(Effect.HTTP_LISTENER, effects)

        # An alias switched to an account without sudo is refused before submission.
        self.write_config(setting("UNPRIVILEGED_USER"))
        refused = self.apply(plan)
        self.assertEqual((refused.status, refused.execution), (Status.FAILED, "not_submitted"))
        self.assertIsNone(refused.dispatched_at)
        self.assertEqual(self.units(), [])
        self.assert_php_not_installed()
        self.write_config(setting("USER"))

        # The connection is lost while the worker watches: the run reconciles, and the
        # installation continues on the server, owned by systemd.
        plan = self.php_plan()
        with self.losing(is_inspection, after=False):
            run = self.apply(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        self.wait_terminal(run.unit_name, timeout=300)
        run = self.check(run)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual((run.execution, run.verification), (Execution.SUCCEEDED, "passed"))
        self.assertEqual(self.units(), [run.unit_name])
        # The guard admitted APT's transaction, epoch archive name included, once.
        journal = self.journal(run.unit_name)
        self.assertEqual(journal.count(native.GUARD_ADMITTED + "\n"), 1)
        self.assertLess(journal.index(native.GUARD_ADMITTED), journal.index("Unpacking "))
        self.assertIn(f"configuration file {ETC}/fpm/php-fpm.conf test is successful", journal)
        # Exactly the reviewed versions; the roots manual, the new dependencies automatic,
        # every other package's mark kept; and Nginx still absent.
        for name, shown in self.status(*installs).items():
            self.assertEqual(shown, f"{installs[name]} ii")
        self.assertEqual(
            sorted(self.administer(f"apt-mark showmanual {PHP_FPM} {PHP_CLI}").split()),
            [PHP_CLI, PHP_FPM],
        )
        dependencies = set(installs) - {PHP_FPM, PHP_CLI}
        automatic_after = set(self.administer("apt-mark showauto").split())
        self.assertEqual(automatic_after - dependencies, automatic_before)
        self.assertLessEqual(dependencies, automatic_after)
        self.assertFalse(self.installed("nginx"))
        self.assert_serving()
        # Discovery was refreshed and observes the packages, the unit and the www pool.
        attempt = DiscoveryAttempt.objects.filter(server=self.server).latest("pk")
        self.assertEqual(attempt.status, Status.SUCCEEDED, attempt.failure)
        php = ComponentObservation.objects.get(snapshot__attempt=attempt, component="php-fpm")
        self.assertIn(f"{PHP_FPM} {installs[PHP_FPM]}", php.packages.splitlines())
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Applied and verified")
        self.assertContains(page, "collected after this run finished")

        # Repeating the profile reviews no changes and never runs APT.
        again = self.plan("php")
        self.assertTrue(again.no_changes)
        self.client.post(f"/plans/{again.pk}/apply/")
        self.assertFalse(ApplyRun.objects.filter(plan_number=again.pk).exists())

        # An independent controller, database and alias reconstructs the same state.
        result = self.reconstruct()
        self.assertIn(f"{PHP_FPM} {installs[PHP_FPM]}", result.packages)
        self.assertIn(f"{PHP_FPM}.service active enabled", result.units)
        self.assertTrue(result.eligible and result.no_changes, result)

    def reconstruct(self) -> Reconstructed:
        directory = self.directory / "fresh"
        directory.mkdir()
        config = directory / "config"
        self.write_config(setting("USER"), config)
        completed = subprocess.run(  # noqa: S603 - the test's own script
            [
                sys.executable,
                "-c",
                RECONSTRUCTION,
                str(directory / "db.sqlite3"),
                str(config),
                str(TEST_MANIFEST),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-3000:])
        return Reconstructed(**json.loads(completed.stdout.strip().splitlines()[-1]))

    def test_drift_guard_and_a_partial_baseline_that_keeps_its_marks(self) -> None:
        self.remove_php()
        # A dependency installed outside Barectl between review and the lock is drift,
        # refused before APT runs.
        plan = self.php_plan()
        install_common = (
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download php-common"
        )
        purge_common = "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq php-common >/dev/null"
        self.administer(f"{install_common} >/dev/null")
        before = self.administer(PACKAGE_STATE)
        run = self.apply(plan)
        self.assertEqual(run.execution, Execution.DRIFT, run.failure)
        self.assertNotIn("Reading package lists", self.journal(run.unit_name))
        self.assertEqual(self.administer(PACKAGE_STATE), before)
        self.assert_php_not_installed()
        self.administer(purge_common)

        # The same change between revalidation and APT's resolution: the guard refuses
        # APT's transaction, which lacks it, before dpkg changes anything.
        plan = self.php_plan()
        name = self.submit(
            lambda unit, boot, deadline: self.payload(plan, unit, boot, deadline).replace(
                "b=$(sha256sum", f"{install_common}; b=$(sha256sum", 1
            )
        )
        self.wait_terminal(name, timeout=300)
        self.assertEqual(self.inspect(name).execution, Execution.TRANSACTION_REFUSED)
        self.assertIn(f"{native.GUARD_REFUSED} transaction", self.journal(name))
        self.assert_php_not_installed()
        self.administer(purge_common)

        # A healthy partial baseline: the CLI installed as a dependency of something else.
        # Only FPM is named to APT, so the CLI stays automatic.
        self.administer(
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download {PHP_CLI} "
            f">/dev/null; apt-mark auto {PHP_CLI} >/dev/null"
        )
        automatic_before = set(self.administer("apt-mark showauto").split())
        plan = self.php_plan()
        self.assertEqual(
            list(plan.roots.values_list("name", "installed")),
            [(PHP_FPM, False), (PHP_CLI, True)],
        )
        self.assertEqual(set(plan.transitions.values_list("package", flat=True)), {PHP_FPM})
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED)
        self.assertEqual(self.administer(f"apt-mark showauto {PHP_CLI}").split(), [PHP_CLI])
        self.assertEqual(self.administer(f"apt-mark showmanual {PHP_FPM}").split(), [PHP_FPM])
        self.assertEqual(set(self.administer("apt-mark showauto").split()), automatic_before)
        self.assert_serving()

    def payload(self, plan: ConfigurationPlan, unit: str, boot: str, deadline: int) -> str:
        """The payload Barectl's worker would submit for ``plan``."""
        evidence = dict(plan.evidence.values_list("kind", "fingerprint"))
        return native.package_change(
            unit,
            boot,
            deadline,
            apt=evidence[PlanEvidence.Kind.APT_REVALIDATION],
            packages=evidence[PlanEvidence.Kind.PACKAGE_REVALIDATION],
            scope=PHP.revalidation,
            roots=[(root.name, root.version) for root in plan.roots.filter(installed=False)],
            actions=[
                native.PackageAction(
                    transition.step == PackageTransition.Step.INSTALL,
                    transition.package,
                    transition.version,
                    transition.architecture,
                )
                for transition in plan.transitions.all()
            ],
            services=PHP.units,
            enable=False,
            start=False,
            check=PHP.check,
        )

    def test_a_satisfied_older_release_is_left_alone_while_newer_candidates_exist(self) -> None:
        self.remove_php()
        # The administrator installed the release pocket's version; the updates pocket
        # offers a newer one.
        packages = " ".join(
            f"{name}={OLDER}" for name in PHP_PACKAGES.split() if name.startswith(f"php{VERSION}-")
        )
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o "
            f"APT::Install-Recommends=0 {packages} >/dev/null"
        )
        policy = self.administer(f"LC_ALL=C apt-cache policy {PHP_FPM}")
        installed = re.search(r"Installed: (\S+)", policy)
        candidate = re.search(r"Candidate: (\S+)", policy)
        self.assertIsNotNone(installed)
        self.assertIsNotNone(candidate)
        if installed and candidate:
            self.assertEqual(installed[1], OLDER)
            self.assertNotEqual(candidate[1], OLDER)
        before = self.administer(PACKAGE_STATE)
        with self.recording() as commands:
            plan = self.php_plan()
        self.assertTrue(plan.no_changes)
        self.assertEqual(
            set(plan.roots.values_list("name", "version", "installed")),
            {(PHP_FPM, OLDER, True), (PHP_CLI, OLDER, True)},
        )
        # Nothing simulated an installation, and nothing can be applied.
        self.assertFalse([c for c in commands if "apt-get -s" in c])
        self.assertNotContains(self.client.get(f"/plans/{plan.pk}/"), "Apply plan")
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertFalse(ApplyRun.objects.exists())
        self.assertEqual(self.units(), [])
        self.assertEqual(self.administer(PACKAGE_STATE), before)


class PhpServiceTests(PhpAcceptanceTestCase):
    def test_service_effects_and_refusals_on_the_provisioned_php(self) -> None:
        # An administrator stops and disables PHP-FPM outside Barectl; discovery sees it.
        self.administer(f"systemctl disable --now -q {PHP_FPM}")
        request_discovery(self.server)
        run_worker()
        php = ComponentObservation.objects.filter(
            snapshot__server=self.server, component="php-fpm"
        ).latest("pk")
        unit = php.service_units.get(name=f"{PHP_FPM}.service")
        self.assertEqual((unit.active_state, unit.unit_file_state), ("inactive", "disabled"))
        # The review proposes only enabling and starting, applied without APT.
        plan = self.php_plan()
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [Effect.SERVICE_ENABLE, Effect.SERVICE_START, Effect.LOCAL_SOCKET],
        )
        before = self.administer(PACKAGE_STATE)
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED)
        journal = self.journal(run.unit_name)
        self.assertNotIn("Reading package lists", journal)
        self.assertIn("test is successful", journal)
        self.assertEqual(self.administer(PACKAGE_STATE), before)
        self.assert_serving()
        self.assertTrue(DiscoveryAttempt.objects.filter(server=self.server).count() >= 2)

        for change, undo, reason, named in (
            (
                f"systemctl mask -q {PHP_FPM}",
                f"systemctl unmask -q {PHP_FPM}",
                Reason.SERVICE_UNIT,
                "masked",
            ),
            (
                f"cp {ETC}/fpm/pool.d/www.conf {ETC}/fpm/pool.d/shop.conf",
                f"rm {ETC}/fpm/pool.d/shop.conf",
                Reason.CUSTOMIZED,
                f"{ETC}/fpm/pool.d/shop.conf",
            ),
            (
                (
                    f"cp {ETC}/fpm/pool.d/www.conf /root/www.conf; "
                    f"echo 'pm.max_children = 9' >>{ETC}/fpm/pool.d/www.conf"
                ),
                f"mv /root/www.conf {ETC}/fpm/pool.d/www.conf",
                Reason.CUSTOMIZED,
                "www.conf (changed",
            ),
            (
                "mkdir -p /etc/php/8.2/fpm",
                "rm -rf /etc/php/8.2",
                Reason.UNSUPPORTED_VERSION,
                "/etc/php/8.2",
            ),
        ):
            with self.subTest(reason=reason, named=named):
                self.administer(change)
                refused = self.plan("php")
                self.assertIn(reason, refused.refusals.values_list("reason", flat=True))
                self.assertTrue(refused.refusals.filter(text__contains=named).exists())
                self.administer(undo)
        # Another process listens on the default pool's socket while PHP-FPM is stopped.
        self.administer(f"systemctl stop {PHP_FPM}")
        self.administer(
            f"exec python3 -c {shlex.quote(SOCKET_HOLDER)} barectl-test-socket", detach=True
        )
        time.sleep(1)
        refused = self.plan("php")
        self.assertEqual(set(refused.refusals.values_list("reason", flat=True)), {Reason.LISTENER})
        self.administer(
            f"pkill -f '[b]arectl-test-socket'; rm -f {PHP.socket}; systemctl start {PHP_FPM}"
        )
        # Undone, the provisioned PHP is a plan without changes again.
        self.assertTrue(self.plan("php").no_changes)


class CrossProfileTests(PhpAcceptanceTestCase):
    def test_nginx_and_php_applied_together_from_two_controllers_admit_one(self) -> None:
        self.administer(REMOVE_NGINX)
        self.addCleanup(self.administer, RESTORE_NGINX)
        self.remove_php()
        profiles = {"a": ("disposable", "nginx"), "b": ("disposable-second", "php")}
        for name, (alias, action) in profiles.items():
            prepared = self.finish(self.controller(name, alias, "prepare", action))
            self.assertTrue(prepared["eligible"], prepared)
        before = self.administer(PACKAGE_STATE)
        racing = [
            self.controller(name, alias, "apply", action)
            for name, (alias, action) in profiles.items()
        ]
        results = dict(zip(profiles, (self.finish(process) for process in racing), strict=True))
        executions = {name: str(result["execution"]) for name, result in results.items()}
        succeeded = [
            name for name, result in results.items() if result["status"] == Status.SUCCEEDED
        ]
        # At most one profile changed the server. The other stopped under the lock before
        # APT ran: it found the lock taken, the other run's processes, or, if it started
        # after the other finished, the changed package state.
        self.assertLessEqual(len(succeeded), 1, executions)
        for name, result in results.items():
            if name in succeeded:
                continue
            self.assertIn(
                result["execution"],
                {Execution.LOCK_CONFLICT, Execution.OTHER_RUN_ACTIVE, Execution.DRIFT},
                executions,
            )
            self.assertNotIn("Reading package lists", self.journal(str(result["unit"])))
        installed = {"a": self.installed("nginx"), "b": self.installed(PHP_FPM)}
        self.assertEqual({name for name, done in installed.items() if done}, set(succeeded))
        if not succeeded:
            self.assertEqual(self.administer(PACKAGE_STATE), before)
