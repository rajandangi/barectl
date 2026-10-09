"""Exact reviewed PostgreSQL installation on a real, disposable Ubuntu server.

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The tests reuse the engine and the database
profile extension MariaDB qualified; they establish what is specific to the PostgreSQL
profile: the release-default major's actual package closure, pg_createcluster's main
cluster, its real cluster unit beside the umbrella unit, postgres's peer access through the
local socket, the loopback-only listeners, a satisfied cluster whose data a repeated review
leaves alone, the refusals of extra clusters, custom authentication, listeners and missing
archive components, a partly created cluster, and faults: drift, the runtime limit, a lost
acknowledgement and two controllers racing. Every run goes through actual APT, dpkg,
debconf, PostgreSQL and systemd; ground truth is read through ``docker exec``. The
provisioned server's PostgreSQL has extra clusters; each test removes PostgreSQL and
restores the provisioned installation and clusters afterwards.
"""

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from dashboard.testing import TEST_MANIFEST
from discovery.models import ComponentObservation, DiscoveryAttempt
from discovery.native_testing import setting
from operations.models import RemoteOperation

from . import native, profiles
from .apply_remote_testing import is_submission
from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
)
from .native_testing import RELEASE
from .test_coordination_remote import ControllerTestCase
from .test_mariadb_remote import assert_documented_sudoers

Status = RemoteOperation.Status
Effect = PlanEffect.Kind
Reason = PlanRefusal.Reason
POSTGRESQL = profiles.profile(RELEASE, Action.POSTGRESQL)
MAJOR = RELEASE.postgresql.major
CLUSTER = f"postgresql@{MAJOR}-main"
PSQL = "runuser -u postgres -- psql -X -A -t -q -d postgres"
# Take PostgreSQL away, clusters, data and configuration included, as a server without it.
REMOVE_POSTGRESQL = (
    "systemctl stop postgresql 'postgresql@*' 2>/dev/null; "
    "export DEBIAN_FRONTEND=noninteractive; dpkg --configure -a >/dev/null 2>&1; "
    "apt-get purge -y -qq postgresql 'postgresql-[0-9]*' 'postgresql-client-[0-9]*' "
    "postgresql-common postgresql-client-common >/dev/null 2>&1; "
    "rm -rf /etc/postgresql /etc/postgresql-common /var/lib/postgresql /var/log/postgresql "
    "/var/run/postgresql; systemctl daemon-reload; true"
)
# Put the provisioned PostgreSQL back from APT's cache, with its extra clusters.
RESTORE_POSTGRESQL = (
    f"{REMOVE_POSTGRESQL}; set -e; export DEBIAN_FRONTEND=noninteractive; "
    "apt-get install -y -qq --no-download postgresql >/dev/null; "
    f"pg_createcluster {MAJOR} archive >/dev/null; "
    f"pg_createcluster {MAJOR} reports --start-conf manual >/dev/null; systemctl daemon-reload"
)
PACKAGE_STATE = (
    "sha256sum /var/lib/dpkg/status /var/lib/apt/extended_states | cut -d' ' -f1; "
    "wc -l </var/log/dpkg.log"
)
SENTINEL = (
    f"{PSQL} -c 'CREATE DATABASE barectl_sentinel' && "  # noqa: S608 - fixed fixture
    "runuser -u postgres -- psql -X -q -d barectl_sentinel "
    "-c \"CREATE TABLE kept (value text); INSERT INTO kept VALUES ('kept-by-operator')\""
)
READ_SENTINEL = (
    "runuser -u postgres -- psql -X -A -t -q -d barectl_sentinel -c 'SELECT value FROM kept'"
)
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
postgresql = ComponentObservation.objects.get(component="postgresql")
client = Client()
client.force_login(user)
client.post(f"/servers/{server.pk}/plans/prepare/", {"action": "postgresql"}, secure=True)
run_worker()
plan = ConfigurationPlan.objects.get()
print(json.dumps({
    "packages": postgresql.packages.splitlines(),
    "units": [
        f"{u.name} {u.active_state} {u.sub_state}" for u in postgresql.service_units.all()
    ],
    "no_changes": plan.no_changes,
    "eligible": plan.eligible,
    "administration": plan.evidence.get(kind="administration").summary,
}))
"""
PROVEN = "The administrative check ran with privilege."


@dataclass(frozen=True)
class Reconstructed:
    packages: list[str]
    units: list[str]
    no_changes: bool
    eligible: bool
    administration: str


class PostgreSQLAcceptanceTestCase(ControllerTestCase):
    """The disposable server without PostgreSQL, restored to its provisioned clusters."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.user.user_permissions.add(Permission.objects.get(codename="add_discoveryattempt"))
        self.administer(REMOVE_POSTGRESQL)
        self.addCleanup(self.administer, RESTORE_POSTGRESQL)
        self.logged = int(self.administer("wc -l </var/log/dpkg.log"))

    def postgresql_plan(self) -> ConfigurationPlan:
        plan = self.plan("postgresql")
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
        self.assertFalse(self.installed(f"postgresql-{MAJOR}"))
        since = self.administer(f"tail -n +{self.logged + 1} /var/log/dpkg.log")
        self.assertNotRegex(since, rf" (install|configure) postgresql-{MAJOR}:")

    def install(self) -> None:
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o APT::Install-Recommends=0 "
            f"postgresql-{MAJOR} >/dev/null"
        )

    def assert_ready(self) -> None:
        """The release-default major's main cluster, running as the distribution made it."""
        self.assertEqual(
            self.administer(
                f"systemctl show -p ActiveState -p SubState --value postgresql {CLUSTER}"
            ).split(),
            ["active", "exited", "active", "running"],
        )
        self.assertEqual(
            self.administer("pg_lsclusters -h").split()[:4], [MAJOR, "main", "5432", "online"]
        )
        self.assertEqual(len(self.administer("pg_lsclusters -h").splitlines()), 1)
        self.assertEqual(
            self.administer(
                f"{PSQL} -c 'SELECT current_user, version() LIKE $$PostgreSQL {MAJOR}.%$$'"
            ).split(),
            ["postgres|t"],
        )
        listening = sorted(
            line.split()[3] for line in self.administer("ss -Hltn sport = :5432").splitlines()
        )
        self.assertEqual(listening, ["127.0.0.1:5432", "[::1]:5432"])
        self.assertIn(POSTGRESQL.socket or "", self.administer(f"ss -Hlx src {POSTGRESQL.socket}"))

    def payload(self, plan: ConfigurationPlan, unit: str, boot: str, deadline: int) -> str:
        evidence = dict(plan.evidence.values_list("kind", "fingerprint"))
        return native.package_change(
            unit,
            boot,
            deadline,
            apt=evidence[PlanEvidence.Kind.APT_REVALIDATION],
            packages=evidence[PlanEvidence.Kind.PACKAGE_REVALIDATION],
            scope=POSTGRESQL.revalidation,
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
            services=POSTGRESQL.units,
            enable=False,
            start=False,
            check=POSTGRESQL.check,
        )


class PostgreSQLInstallationTests(PostgreSQLAcceptanceTestCase):
    def test_an_installation_is_exact_ready_preserves_data_and_is_reconstructed(self) -> None:
        automatic_before = set(self.administer("apt-mark showauto").split())
        plan = self.postgresql_plan()
        installs = dict(
            plan.transitions.filter(step=PackageTransition.Step.INSTALL).values_list(
                "package", "version"
            )
        )
        simulated = self.administer(
            "LC_ALL=C apt-get -s -o APT::Install-Recommends=0 -o APT::Install-Suggests=0 "
            f"install postgresql-{MAJOR}"
        )
        self.assertEqual(
            installs, dict(re.findall(r"^Inst (\S+) \((\S+) ", simulated, re.MULTILINE))
        )
        policy = self.administer(f"LC_ALL=C apt-cache policy postgresql-{MAJOR}")
        candidate = re.search(r"Candidate: (\S+)", policy)
        self.assertEqual(installs[f"postgresql-{MAJOR}"], candidate[1] if candidate else "")
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
        self.assertEqual(components, {"main"})

        # The submission's answer is lost after it reached the server: the run reconciles,
        # the installation continues under systemd, and Check outcome records it.
        with self.losing(is_submission, after=True):
            run = self.apply(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        self.wait_terminal(run.unit_name, timeout=300)
        run = self.check(run)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual((run.execution, run.verification), (Execution.SUCCEEDED, "passed"))
        journal = self.journal(run.unit_name)
        self.assertEqual(journal.count(native.GUARD_ADMITTED + "\n"), 1)
        self.assertIn(f"{POSTGRESQL.check.expected}\n", journal)
        for name, version in installs.items():
            shown = self.administer(f"dpkg-query -W -f='${{Version}} ${{db:Status-Abbrev}}' {name}")
            self.assertEqual(shown.strip(), f"{version} ii")
        dependencies = set(installs) - {f"postgresql-{MAJOR}"}
        automatic_after = set(self.administer("apt-mark showauto").split())
        self.assertEqual(automatic_after - dependencies, automatic_before)
        self.assert_ready()
        # No database or role besides the distribution's, and no password.
        self.assertEqual(
            self.administer(f"{PSQL} -c 'SELECT datname FROM pg_database ORDER BY 1'").split(),  # noqa: S608
            ["postgres", "template0", "template1"],
        )
        self.assertEqual(
            self.administer(
                f"{PSQL} -c 'SELECT count(*) FROM pg_authid WHERE rolpassword IS NOT NULL'"  # noqa: S608
            ).strip(),
            "0",
        )
        attempt = DiscoveryAttempt.objects.filter(server=self.server).latest("pk")
        self.assertEqual(attempt.status, Status.SUCCEEDED, attempt.failure)
        observed = ComponentObservation.objects.get(
            snapshot__attempt=attempt, component="postgresql"
        )
        unit = observed.service_units.get(name=f"{CLUSTER}.service")
        self.assertEqual((unit.active_state, unit.sub_state), ("active", "running"))

        # An operator's data survives a repeated review, which has no changes to apply.
        self.administer(SENTINEL)
        again = self.plan("postgresql")
        self.assertTrue(again.eligible and again.no_changes, self.texts(again))
        self.assertEqual(again.evidence.get(kind="administration").summary, PROVEN)
        self.client.post(f"/plans/{again.pk}/apply/")
        self.assertFalse(ApplyRun.objects.filter(plan_number=again.pk).exists())
        self.assertEqual(self.administer(READ_SENTINEL).strip(), "kept-by-operator")

        # An independent controller reconstructs the actual cluster and its readiness.
        result = self.reconstruct()
        self.assertIn(f"postgresql-{MAJOR} {installs[f'postgresql-{MAJOR}']}", result.packages)
        self.assertEqual(
            result.units,
            ["postgresql.service active exited", f"{CLUSTER}.service active running"],
        )
        self.assertTrue(result.eligible and result.no_changes, result)
        self.assertEqual(result.administration, PROVEN)
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

    def test_an_unapplied_or_stopped_configuration_is_refused_and_data_kept(self) -> None:
        self.install()
        self.administer(SENTINEL)
        before = self.administer(PACKAGE_STATE)
        failure = profiles.profile(RELEASE, Action.POSTGRESQL).readiness_failure
        # ALTER SYSTEM, not yet applied: the running server's settings still look default.
        self.administer(f"{PSQL} -c \"ALTER SYSTEM SET listen_addresses = '*'\"")
        refused = self.plan("postgresql")
        self.assertEqual(self.texts(refused), [failure])
        # Stopped with that change waiting: the review never starts the cluster.
        self.administer(f"systemctl stop {CLUSTER}")
        refused = self.plan("postgresql")
        self.assertEqual(self.reasons(refused), {Reason.SERVICE_UNIT})
        self.assertIn(
            f"{CLUSTER}.service is not active and enabled (inactive,", self.texts(refused)[0]
        )
        self.assertEqual(self.units(), [])
        self.administer(
            f"systemctl start {CLUSTER}; {PSQL} -c 'ALTER SYSTEM RESET ALL'; "
            f"systemctl restart {CLUSTER}"
        )
        # pg_hba.conf changed on disk but not reloaded: the loaded rules may differ.
        hba = f"/etc/postgresql/{MAJOR}/main/pg_hba.conf"
        self.administer(f"sleep 1; touch {hba}")
        refused = self.plan("postgresql")
        self.assertEqual(self.texts(refused), [failure])
        self.administer(f"systemctl reload {CLUSTER}; sleep 1")
        again = self.plan("postgresql")
        self.assertTrue(again.no_changes, self.texts(again))
        self.assertEqual(self.administer(PACKAGE_STATE), before)
        self.assertEqual(self.administer(READ_SENTINEL).strip(), "kept-by-operator")
        # psql's history under the data root is not data: the digest applying rechecks,
        # computed as root on the server, is unchanged and the review still no-op.
        digest = again.evidence.get(kind=PlanEvidence.Kind.PACKAGE_REVALIDATION).fingerprint
        self.administer(
            "install -o postgres -g postgres -m 600 /dev/null /var/lib/postgresql/.psql_history"
        )
        shown = self.administer(POSTGRESQL.revalidation).split()[0]
        self.assertEqual(shown, digest)
        self.assertTrue(self.plan("postgresql").no_changes)

    def test_the_documented_sudoers_rule_proves_readiness_with_sudo_only(self) -> None:
        self.install()
        assert_documented_sudoers(self, POSTGRESQL, "postgresql")


class PostgreSQLAdmissionTests(PostgreSQLAcceptanceTestCase):
    def test_extra_clusters_custom_access_and_partial_clusters_are_refused(self) -> None:
        self.install()
        self.administer(SENTINEL)
        before = self.administer(PACKAGE_STATE)
        # Another cluster of the default major, as the provisioned server has.
        self.administer(f"pg_createcluster {MAJOR} archive >/dev/null")
        refused = self.plan("postgresql")
        self.assertIn(Reason.CUSTOMIZED, self.reasons(refused))
        self.assertIn(f"/etc/postgresql/{MAJOR}/archive", " ".join(self.texts(refused)))
        self.administer(f"pg_dropcluster {MAJOR} archive")
        # A trust rule ahead of the distribution's rules: custom authentication.
        hba = f"/etc/postgresql/{MAJOR}/main/pg_hba.conf"
        self.administer(
            f"cp -p {hba} /root/pg_hba.conf; sed -i '1i local all all trust' {hba}; "
            f"systemctl reload {CLUSTER}"
        )
        refused = self.plan("postgresql")
        self.assertIn(Reason.ADMINISTRATION, self.reasons(refused))
        self.administer(f"cp -p /root/pg_hba.conf {hba}; systemctl reload {CLUSTER}")
        # A configuration file opening every address.
        self.administer(
            f"echo \"listen_addresses = '*'\" >/etc/postgresql/{MAJOR}/main/conf.d/listen.conf; "
            f"systemctl restart {CLUSTER}"
        )
        refused = self.plan("postgresql")
        self.assertLessEqual({Reason.CUSTOMIZED, Reason.LISTENER}, self.reasons(refused))
        self.administer(
            f"rm /etc/postgresql/{MAJOR}/main/conf.d/listen.conf; systemctl restart {CLUSTER}"
        )
        # The configuration is present and the data directory empty, as a partly created
        # cluster leaves it: the review refuses, and never starts or initializes it.
        data = f"/var/lib/postgresql/{MAJOR}/main"
        self.administer(
            f"systemctl stop {CLUSTER}; mv {data} /root/pg-main; "
            f"install -d -o postgres -g postgres -m 700 {data}"
        )
        refused = self.plan("postgresql")
        self.assertEqual(self.reasons(refused), {Reason.SERVICE_UNIT})
        self.assertEqual(
            self.texts(refused),
            [
                (
                    f"{CLUSTER}.service is not active and enabled (inactive, enabled-runtime). "
                    "Bootstrap establishes only a running cluster, whose administration it can "
                    "check, and never starts one it did not create, which may be partly "
                    "initialized. Start the cluster through ordinary administration, such as sudo "
                    f"pg_ctlcluster {MAJOR} main start, then prepare again."
                )
            ],
        )
        self.assertEqual(self.administer(f"ls -A {data}").strip(), "")
        # Nothing Barectl did changed a package.
        self.assertEqual(self.administer(PACKAGE_STATE), before)
        # Ordinary administration restores the data and starts it; it is established again.
        self.administer(f"rmdir {data}; mv /root/pg-main {data}; systemctl start {CLUSTER}")
        again = self.plan("postgresql")
        self.assertTrue(again.eligible and again.no_changes, self.texts(again))

    def test_missing_components_drift_and_the_runtime_limit_change_nothing(self) -> None:
        # The release's main index of one suite is gone: installing needs it.
        lists = f"/var/lib/apt/lists/*_dists_{RELEASE.codename}-updates_main_binary-*_Packages*"
        self.administer(f"mkdir -p /root/lists; mv {lists} /root/lists/")
        refused = self.plan("postgresql")
        self.administer("mv /root/lists/* /var/lib/apt/lists/")
        self.assertIn(Reason.PACKAGE_METADATA, self.reasons(refused))
        self.assertIn(f"{RELEASE.codename}-updates main", " ".join(self.texts(refused)))
        # A dependency installed outside Barectl between review and the lock.
        plan = self.postgresql_plan()
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download "
            "postgresql-client-common >/dev/null"
        )
        before = self.administer(PACKAGE_STATE)
        run = self.apply(plan)
        self.assertEqual(run.execution, Execution.DRIFT, run.failure)
        self.assertNotIn("Reading package lists", self.journal(run.unit_name))
        self.assertEqual(self.administer(PACKAGE_STATE), before)
        self.assert_not_installed()
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq postgresql-client-common "
            ">/dev/null"
        )
        # The runtime limit stops a run held before APT.
        plan = self.postgresql_plan()
        before = self.administer(PACKAGE_STATE)
        with mock.patch.object(native, "RUNTIME_MAX", "3s"):
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


class PostgreSQLCoordinationTests(PostgreSQLAcceptanceTestCase):
    def test_two_controllers_installing_postgresql_admit_at_most_one(self) -> None:
        controllers = {"a": "disposable", "b": "disposable-second"}
        for name, alias in controllers.items():
            prepared = self.finish(self.controller(name, alias, "prepare", "postgresql"))
            self.assertTrue(prepared["eligible"], prepared)
        racing = [
            self.controller(name, alias, "apply", "postgresql")
            for name, alias in controllers.items()
        ]
        results = dict(zip(controllers, (self.finish(process) for process in racing), strict=True))
        executions = {name: str(result["execution"]) for name, result in results.items()}
        succeeded = [n for n, result in results.items() if result["status"] == Status.SUCCEEDED]
        self.assertLessEqual(len(succeeded), 1, executions)
        stopped = {Execution.LOCK_CONFLICT, Execution.OTHER_RUN_ACTIVE}
        allowed = {*stopped, Execution.DRIFT} if succeeded else stopped
        for name, result in results.items():
            if name in succeeded:
                continue
            self.assertIn(result["execution"], allowed, executions)
            self.assertNotIn("Reading package lists", self.journal(str(result["unit"])))
        if not succeeded:
            self.assert_not_installed()
            run = self.apply(self.postgresql_plan())
            self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assert_ready()
