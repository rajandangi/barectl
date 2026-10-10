"""Exact reviewed MariaDB installation on a real, disposable Ubuntu server.

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The tests reuse the engine Nginx and PHP
qualified; they establish what is specific to the MariaDB profile: the release's actual
package closure from its archive components, the maintainer scripts' initialization,
root's local socket access, the loopback-only listener, the data directory, a satisfied
engine whose data a repeated review leaves alone, the refusals of conflicting MySQL
packages, data directories and custom listeners, and faults: drift, an interrupted
transaction, the runtime limit, a lost connection and two controllers racing. Every run goes
through actual APT, dpkg, debconf, MariaDB and systemd; ground truth is read through
``docker exec``. The provisioned server has no MariaDB; each test removes what it installed,
data directories included.
"""

import json
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, override
from unittest import mock

from django.contrib.auth.models import Permission

from dashboard.testing import TEST_MANIFEST
from discovery.fakes import run_worker
from discovery.models import ComponentObservation, DiscoveryAttempt
from discovery.test_remote import setting
from operations import native as operations_native
from operations.models import RemoteOperation

from . import native, profiles
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
from .native_testing import (
    INSTALL_MARIADB as INSTALL_MARIADB,
)
from .native_testing import (
    MARIADB as MARIADB,
)
from .native_testing import (
    PACKAGES as PACKAGES,
)
from .native_testing import (
    RECOVER as RECOVER,
)
from .native_testing import (
    RELEASE as RELEASE,
)
from .native_testing import (
    REMOVE_MARIADB as REMOVE_MARIADB,
)
from .test_coordination_remote import ControllerTestCase

if TYPE_CHECKING:
    from .apply_remote_testing import ApplyAcceptanceTestCase


def assert_documented_sudoers(
    case: ApplyAcceptanceTestCase, profile: profiles.Profile, action: str
) -> None:
    """docs/bootstrap.md#authorizing-readiness-checks: the documented rule, for an SSH user
    whose sudo authorizes nothing else, proves an established engine's readiness with the
    original sudo; sudo-rs cannot match it, and the review is refused as unverified."""
    rule = (
        "deploy ALL=(root) NOPASSWD: /usr/bin/systemd-run\n"
        f"deploy ALL=(root) NOPASSWD: {profile.check.sudoers}\n"
    )
    case.administer("cp /etc/sudoers.d/deploy /root/sudoers-deploy")
    restore = (
        "cp /root/sudoers-deploy /etc/sudoers.d/deploy; "
        "update-alternatives --quiet --auto sudo 2>/dev/null; true"
    )
    case.addCleanup(case.administer, restore)
    providers = {"sudo": ""}
    if RELEASE.version == "26.04":
        providers = {
            "sudo-rs": "",
            "sudo.ws": "update-alternatives --quiet --set sudo /usr/bin/sudo.ws",
        }
    for provider, select in providers.items():
        with case.subTest(provider=provider):
            case.administer(
                f"{select + '; ' if select else ''}"
                f"printf %s {shlex.quote(rule)} >/etc/sudoers.d/deploy; "
                "chmod 440 /etc/sudoers.d/deploy; visudo -c -q"
            )
            case.client.post(f"/servers/{case.server.pk}/plans/prepare/", {"action": action})
            run_worker()
            plan = ConfigurationPlan.objects.latest("pk")
            reasons = set(plan.refusals.values_list("reason", flat=True))
            if provider == "sudo-rs":
                case.assertEqual(reasons, {PlanRefusal.Reason.ADMINISTRATION})
                case.assertIn(
                    "readiness is unverified",
                    " ".join(plan.refusals.values_list("text", flat=True)),
                )
            else:
                case.assertTrue(plan.no_changes, list(plan.refusals.values_list("text", flat=True)))
                case.assertEqual(
                    plan.evidence.get(kind=PlanEvidence.Kind.ADMINISTRATION).summary,
                    "The administrative check ran with privilege.",
                )
            case.administer(restore)


Status = RemoteOperation.Status
Effect = PlanEffect.Kind
Reason = PlanRefusal.Reason
DATA = RELEASE.mariadb.data
# What must not change when a run stops before dpkg.
PACKAGE_STATE = (
    "sha256sum /var/lib/dpkg/status /var/lib/apt/extended_states | cut -d' ' -f1; "
    "wc -l </var/log/dpkg.log"
)
# Data a database administrator keeps, which no review or run may change.
SENTINEL = (
    'mariadb -e "CREATE DATABASE barectl_sentinel; '
    "CREATE TABLE barectl_sentinel.kept (value VARCHAR(20)); "
    "INSERT INTO barectl_sentinel.kept VALUES ('kept-by-operator')\""
)
READ_SENTINEL = "mariadb -N -B -e 'SELECT value FROM barectl_sentinel.kept'"
# A process listening on MariaDB's port while MariaDB does not run.
LISTENER = (
    "import socket, time; s = socket.socket(); "
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
    "s.bind(('127.0.0.1', 3306)); s.listen(); time.sleep(300)"
)
# A package that stands for an installed MySQL server, built without the network.
FAKE_MYSQL = (
    "set -e; mkdir -p /root/mysql-server/DEBIAN; "
    "printf '%s\\n' 'Package: mysql-server-8.0' 'Version: 0.1-barectl' 'Architecture: all' "
    "'Maintainer: Test <test@example.invalid>' 'Description: Stand-in MySQL server' "
    ">/root/mysql-server/DEBIAN/control; "
    "dpkg-deb --root-owner-group --build /root/mysql-server /root/mysql-server.deb >/dev/null; "
    "dpkg -i /root/mysql-server.deb >/dev/null"
)
# A new, independent controller in its own process and database: it registers the server
# through the second alias and key, discovers it, and reviews the MariaDB profile.
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
mariadb = ComponentObservation.objects.get(component="mariadb")
client = Client()
client.force_login(user)
client.post(f"/servers/{server.pk}/plans/prepare/", {"action": "mariadb"}, secure=True)
run_worker()
plan = ConfigurationPlan.objects.get()
print(json.dumps({
    "packages": mariadb.packages.splitlines(),
    "units": [
        f"{u.name} {u.active_state} {u.sub_state} {u.unit_file_state}"
        for u in mariadb.service_units.all()
    ],
    "no_changes": plan.no_changes,
    "eligible": plan.eligible,
    "administration": plan.evidence.get(kind="administration").summary,
}))
"""


@dataclass(frozen=True)
class Reconstructed:
    """What the independent controller observed and reviewed."""

    packages: list[str]
    units: list[str]
    no_changes: bool
    eligible: bool
    administration: str


class MariaDBAcceptanceTestCase(ControllerTestCase):
    """The disposable server without MariaDB, left that way afterwards."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.user.user_permissions.add(Permission.objects.get(codename="add_discoveryattempt"))
        self.administer(REMOVE_MARIADB)
        self.addCleanup(self.administer, REMOVE_MARIADB)
        self.logged = int(self.administer("wc -l </var/log/dpkg.log"))

    def mariadb_plan(self) -> ConfigurationPlan:
        plan = self.plan("mariadb")
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def texts(self, plan: ConfigurationPlan) -> list[str]:
        return list(plan.refusals.values_list("text", flat=True))

    def reasons(self, plan: ConfigurationPlan) -> set[str]:
        return set(plan.refusals.values_list("reason", flat=True))

    def installed(self, name: str) -> bool:
        shown = self.administer(
            f"dpkg-query -W -f='${{db:Status-Abbrev}}' {name} 2>/dev/null; true"
        )
        return shown.strip() == "ii"

    def assert_not_installed(self) -> None:
        self.assertFalse(self.installed("mariadb-server"))
        since = self.administer(f"tail -n +{self.logged + 1} /var/log/dpkg.log")
        self.assertNotRegex(since, r" (install|configure) mariadb-server:")

    def assert_ready(self) -> None:
        """The engine the distribution initializes: its unit, root's socket access, the
        data directory and the loopback-only listener."""
        self.assertEqual(
            self.administer(
                "systemctl is-enabled mariadb; systemctl show -p ActiveState -p SubState "
                "--value mariadb"
            ).split(),
            ["enabled", "active", "running"],
        )
        # Root authenticates through the socket by its Unix identity, without a password.
        shown = self.administer(
            "mariadb --protocol=socket -N -B -e "
            '"SELECT CURRENT_USER(), @@datadir, @@bind_address, @@port, @@socket"'
        )
        self.assertEqual(
            shown.split(),
            ["root@localhost", f"{DATA}/", "127.0.0.1", "3306", MARIADB.socket or ""],
        )
        self.assertIn(
            "unix_socket",
            self.administer("mariadb -N -B -e \"SHOW CREATE USER 'root'@'localhost'\""),
        )
        self.assertEqual(
            self.administer(f"stat -c '%F %U' {DATA} {DATA}/mysql").splitlines(),
            ["directory mysql", "directory mysql"],
        )
        listening = [
            line.split()[3] for line in self.administer("ss -Hltn sport = :3306").splitlines()
        ]
        self.assertEqual(listening, ["127.0.0.1:3306"])
        self.assertIn(MARIADB.socket or "", self.administer(f"ss -Hlx src {MARIADB.socket}"))

    def payload(self, plan: ConfigurationPlan, unit: str, boot: str, deadline: int) -> str:
        """The payload Barectl's worker would submit for ``plan``."""
        evidence = dict(plan.evidence.values_list("kind", "fingerprint"))
        return native.package_change(
            unit,
            boot,
            deadline,
            apt=evidence[PlanEvidence.Kind.APT_REVALIDATION],
            packages=evidence[PlanEvidence.Kind.PACKAGE_REVALIDATION],
            scope=MARIADB.revalidation,
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
            services=MARIADB.units,
            enable=False,
            start=False,
            check=MARIADB.check,
        )


class MariaDBInstallationTests(MariaDBAcceptanceTestCase):
    def test_an_installation_is_exact_ready_preserves_data_and_is_reconstructed(self) -> None:
        automatic_before = set(self.administer("apt-mark showauto").split())
        plan = self.mariadb_plan()
        installs = dict(
            plan.transitions.filter(step=PackageTransition.Step.INSTALL).values_list(
                "package", "version"
            )
        )
        # The reviewed root is the archive's candidate, and the closure is APT's own.
        policy = self.administer("LC_ALL=C apt-cache policy mariadb-server")
        candidate = re.search(r"Candidate: (\S+)", policy)
        self.assertIsNotNone(candidate)
        if candidate:
            self.assertEqual(installs["mariadb-server"], candidate[1])
        simulated = self.administer(
            "LC_ALL=C apt-get -s -o APT::Install-Recommends=0 -o APT::Install-Suggests=0 "
            "install mariadb-server"
        )
        self.assertEqual(
            installs, dict(re.findall(r"^Inst (\S+) \((\S+) ", simulated, re.MULTILINE))
        )
        # Every reviewed version comes from the release's required archive components.
        offered = self.administer(f"LC_ALL=C apt-cache madison {' '.join(installs)}")
        components = {
            match[3]
            for match in re.finditer(
                r"^ *(\S+) \| *(\S+) \| \S+ [a-z-]+/([a-z]+) [a-z0-9]+ Packages$",
                offered,
                re.MULTILINE,
            )
            if installs.get(match[1]) == match[2]
        }
        self.assertEqual(components, set(MARIADB.components))
        effects = list(plan.effects.values_list("kind", flat=True))
        self.assertIn(Effect.DATA_DIRECTORY, effects)
        self.assertIn(Effect.DATABASE_LISTENERS, effects)
        self.assertFalse([name for name in installs if "php" in name or "mysql-server" in name])

        # The connection is lost while the worker watches: the installation continues on
        # the server, owned by systemd, and Check outcome records it.
        with self.losing(is_inspection, after=False):
            run = self.apply(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        self.wait_terminal(run.unit_name, timeout=300)
        run = self.check(run)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual((run.execution, run.verification), (Execution.SUCCEEDED, "passed"))
        journal = self.journal(run.unit_name)
        self.assertEqual(journal.count(native.GUARD_ADMITTED + "\n"), 1)
        self.assertLess(journal.index(native.GUARD_ADMITTED), journal.index("Unpacking "))
        # The readiness check ran as root at the end of the payload, through the socket.
        self.assertIn(f"{MARIADB.check.expected}\n", journal)
        for name, version in installs.items():
            shown = self.administer(f"dpkg-query -W -f='${{Version}} ${{db:Status-Abbrev}}' {name}")
            self.assertEqual(shown.strip(), f"{version} ii")
        self.assertEqual(
            self.administer("apt-mark showmanual mariadb-server").split(), ["mariadb-server"]
        )
        dependencies = set(installs) - {"mariadb-server"}
        automatic_after = set(self.administer("apt-mark showauto").split())
        self.assertEqual(automatic_after - dependencies, automatic_before)
        self.assertLessEqual(dependencies, automatic_after)
        self.assert_ready()
        upstream = re.sub(r"-[^-]*\Z", "", installs["mariadb-server"].split(":", 1)[1])
        self.assertTrue(
            self.administer("/usr/sbin/mariadbd --version").startswith(
                f"/usr/sbin/mariadbd  Ver {upstream}-MariaDB"
            )
        )
        # The run created no database, database user or password.
        self.assertEqual(
            sorted(self.administer("mariadb -N -B -e 'SHOW DATABASES'").split()),
            ["information_schema", "mysql", "performance_schema", "sys"],
        )
        # Discovery was refreshed and observes the engine.
        attempt = DiscoveryAttempt.objects.filter(server=self.server).latest("pk")
        self.assertEqual(attempt.status, Status.SUCCEEDED, attempt.failure)
        observed = ComponentObservation.objects.get(snapshot__attempt=attempt, component="mariadb")
        self.assertIn(
            f"mariadb-server {installs['mariadb-server']}", observed.packages.splitlines()
        )
        unit = observed.service_units.get(name="mariadb.service")
        self.assertEqual((unit.active_state, unit.sub_state), ("active", "running"))
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Applied and verified")

        # An operator's data survives a repeated review, which has no changes to apply.
        self.administer(SENTINEL)
        again = self.plan("mariadb")
        self.assertTrue(again.eligible and again.no_changes, self.texts(again))
        self.client.post(f"/plans/{again.pk}/apply/")
        self.assertFalse(ApplyRun.objects.filter(plan_number=again.pk).exists())
        self.assertEqual(self.administer(READ_SENTINEL).strip(), "kept-by-operator")

        # An independent controller, database and alias reconstructs the same readiness.
        result = self.reconstruct()
        self.assertIn(f"mariadb-server {installs['mariadb-server']}", result.packages)
        self.assertEqual(result.units, ["mariadb.service active running enabled"])
        self.assertTrue(result.eligible and result.no_changes, result)
        # Its review proved root's socket administration with its own sudo authorization.
        self.assertEqual(result.administration, "The administrative check ran with privilege.")
        self.assertEqual(self.administer(READ_SENTINEL).strip(), "kept-by-operator")

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

    def test_the_documented_sudoers_rule_proves_readiness_with_sudo_only(self) -> None:
        self.administer(INSTALL_MARIADB)
        assert_documented_sudoers(self, MARIADB, "mariadb")

    def test_a_stopped_engine_is_started_and_its_data_kept(self) -> None:
        self.administer(INSTALL_MARIADB)
        self.administer(SENTINEL)
        self.administer("systemctl disable --now -q mariadb")
        plan = self.mariadb_plan()
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [Effect.SERVICE_ENABLE, Effect.SERVICE_START, Effect.DATABASE_LISTENERS],
        )
        before = self.administer(PACKAGE_STATE)
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED)
        self.assertNotIn("Reading package lists", self.journal(run.unit_name))
        self.assertEqual(self.administer(PACKAGE_STATE), before)
        self.assert_ready()
        self.assertEqual(self.administer(READ_SENTINEL).strip(), "kept-by-operator")


class MariaDBAdmissionTests(MariaDBAcceptanceTestCase):
    def test_conflicts_remnants_and_custom_listeners_are_refused_without_changes(self) -> None:
        # A MySQL server's package.
        self.administer(FAKE_MYSQL)
        refused = self.plan("mariadb")
        self.assertIn(Reason.CONFLICT, self.reasons(refused))
        self.assertIn("mysql-server-8.0 0.1-barectl", " ".join(self.texts(refused)))
        self.administer("dpkg --purge mysql-server-8.0 >/dev/null")
        # A data directory without its packages, as a purge leaves it by default: the
        # operator's data stays and the review refuses to adopt it.
        self.administer(INSTALL_MARIADB)
        self.administer(SENTINEL)
        self.administer(
            "systemctl stop mariadb; DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "
            f"{PACKAGES} >/dev/null"
        )
        refused = self.plan("mariadb")
        self.assertIn(Reason.LEFTOVER, self.reasons(refused))
        self.assertIn(DATA, " ".join(self.texts(refused)))
        self.assertIn("barectl_sentinel", self.administer(f"ls {DATA}"))
        self.administer(f"rm -rf {DATA} /etc/mysql")
        # Another process on MariaDB's port.
        self.administer(f'exec python3 -c "{LISTENER}" barectl-test-listener', detach=True)
        time.sleep(1)
        refused = self.plan("mariadb")
        self.assertEqual(self.reasons(refused), {Reason.LISTENER})
        self.administer("pkill -f '[b]arectl-test-listener'")
        # An installed engine an administrator configured to listen on every address.
        self.administer(INSTALL_MARIADB)
        self.administer(
            "printf '[mysqld]\\nbind-address = 0.0.0.0\\n' "
            ">/etc/mysql/mariadb.conf.d/99-listen.cnf; systemctl restart mariadb"
        )
        before = self.administer(PACKAGE_STATE)
        refused = self.plan("mariadb")
        self.assertEqual(self.reasons(refused), {Reason.CUSTOMIZED, Reason.LISTENER})
        self.assertIn("99-listen.cnf", " ".join(self.texts(refused)))
        self.assertIn("port 3306 at 0.0.0.0, not only", " ".join(self.texts(refused)))
        self.assertEqual(self.administer(PACKAGE_STATE), before)
        self.administer("rm /etc/mysql/mariadb.conf.d/99-listen.cnf; systemctl restart mariadb")
        # Option files outside /etc/mysql, and the my.cnf alternative set elsewhere.
        self.administer("printf '[mysqld]\\nskip-networking\\n' >/etc/my.cnf")
        refused = self.plan("mariadb")
        self.assertIn(Reason.LEFTOVER, self.reasons(refused))
        self.assertIn("/etc/my.cnf", " ".join(self.texts(refused)))
        self.administer("rm /etc/my.cnf")
        self.administer("update-alternatives --quiet --set my.cnf /etc/mysql/my.cnf.fallback")
        refused = self.plan("mariadb")
        self.assertIn(Reason.CUSTOMIZED, self.reasons(refused))
        self.assertIn("resolves to /etc/mysql/my.cnf.fallback", " ".join(self.texts(refused)))
        self.administer("update-alternatives --quiet --auto my.cnf")
        # Root's authentication changed inside the database: installed but not established.
        self.administer("mariadb -e \"CREATE USER ''@'localhost'\"")
        refused = self.plan("mariadb")
        self.assertEqual(self.reasons(refused), {Reason.ADMINISTRATION})
        self.assertFalse(refused.no_changes)
        self.administer("mariadb -e \"DROP USER ''@'localhost'\"")
        again = self.plan("mariadb")
        self.assertTrue(again.no_changes, self.texts(again))
        self.assertEqual(
            again.evidence.get(kind="administration").summary,
            "The administrative check ran with privilege.",
        )

    def test_drift_before_apt_and_the_runtime_limit_change_nothing(self) -> None:
        # A dependency installed outside Barectl between review and the lock.
        plan = self.mariadb_plan()
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mysql-common >/dev/null"
        )
        before = self.administer(PACKAGE_STATE)
        run = self.apply(plan)
        self.assertEqual(run.execution, Execution.DRIFT, run.failure)
        self.assertNotIn("Reading package lists", self.journal(run.unit_name))
        self.assertEqual(self.administer(PACKAGE_STATE), before)
        self.assert_not_installed()
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq mysql-common >/dev/null"
        )
        # The runtime limit stops a run held before APT: the whole group ends, the lock is
        # freed, and no package changed.
        plan = self.mariadb_plan()
        before = self.administer(PACKAGE_STATE)
        with mock.patch.object(operations_native, "RUNTIME_MAX", "3s"):
            name = self.submit(
                lambda unit, boot, deadline: self.payload(plan, unit, boot, deadline).replace(
                    "b=$(sha256sum", "sleep 120; b=$(sha256sum", 1
                )
            )
        self.wait_terminal(name, timeout=60)
        self.assertEqual(self.inspect(name).execution, Execution.TIMED_OUT)
        self.assertTrue(self.lock_is_free())
        self.assertEqual(self.administer(PACKAGE_STATE), before)
        self.assert_not_installed()

    def test_an_interrupted_transaction_is_left_for_ordinary_recovery(self) -> None:
        plan = self.mariadb_plan()
        name = self.submit(lambda unit, boot, deadline: self.payload(plan, unit, boot, deadline))
        # The run is killed once dpkg unpacked part of the reviewed transaction.
        self.administer(
            f"for i in $(seq 1500); do tail -n +{self.logged + 1} /var/log/dpkg.log "
            f"| grep -q ' status unpacked ' && break; sleep 0.1; done; "
            f"systemctl kill --signal=SIGKILL {name}"
        )
        self.wait_terminal(name, timeout=120)
        self.assertEqual(self.inspect(name).execution, Execution.KILLED)
        self.assertTrue(self.lock_is_free())
        # dpkg keeps its native diagnostics: its log and its record of the unfinished work.
        self.assertIn(
            " status unpacked ", self.administer(f"tail -n +{self.logged + 1} /var/log/dpkg.log")
        )
        self.assertTrue(self.administer("dpkg --audit; true").strip())
        refused = self.plan("mariadb")
        self.assertFalse(refused.eligible)
        self.assertTrue(
            self.reasons(refused) & {Reason.PACKAGE_HEALTH, Reason.INCOMPLETE}, self.texts(refused)
        )
        # Ordinary administration completes the installation; a fresh review then finds
        # the engine established.
        recovered = subprocess.run(  # noqa: S603 - the test's own fixture script
            ["docker", "exec", setting("CONTAINER"), "sh", "-c", f"{RECOVER}; {INSTALL_MARIADB}"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        self.assertEqual(recovered.returncode, 0, (recovered.stdout + recovered.stderr)[-4000:])
        again = self.plan("mariadb")
        self.assertTrue(again.eligible, self.texts(again))


class MariaDBCoordinationTests(MariaDBAcceptanceTestCase):
    def test_two_controllers_installing_mariadb_admit_at_most_one(self) -> None:
        controllers = {"a": "disposable", "b": "disposable-second"}
        for name, alias in controllers.items():
            prepared = self.finish(self.controller(name, alias, "prepare", "mariadb"))
            self.assertTrue(prepared["eligible"], prepared)
        racing = [
            self.controller(name, alias, "apply", "mariadb") for name, alias in controllers.items()
        ]
        results = dict(zip(controllers, (self.finish(process) for process in racing), strict=True))
        executions = {name: str(result["execution"]) for name, result in results.items()}
        succeeded = [n for n, result in results.items() if result["status"] == Status.SUCCEEDED]
        # At most one installs; both can stop under the lock when each finds the other.
        self.assertLessEqual(len(succeeded), 1, executions)
        # A run that starts after the winner finished sees the changed packages as drift;
        # without a winner, both met each other under the lock.
        stopped = {Execution.LOCK_CONFLICT, Execution.OTHER_RUN_ACTIVE}
        allowed = {*stopped, Execution.DRIFT} if succeeded else stopped
        for name, result in results.items():
            if name in succeeded:
                continue
            self.assertIn(result["execution"], allowed, executions)
            self.assertNotIn("Reading package lists", self.journal(str(result["unit"])))
        if not succeeded:
            self.assert_not_installed()
            # Nothing changed, so a new review installs through this controller.
            run = self.apply(self.mariadb_plan())
            self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assert_ready()
