"""The PostgreSQL profile's review and apply, per supported release.

Real views, services, the worker, persistence and rendering run against a simulated
Ubuntu server whose packages, units, cluster configuration, data directories, listeners
and administrative check are those recorded on each release's disposable server. These
tests establish what the review admits and refuses and what a run submits and verifies;
``bootstrap/test_postgresql_remote.py`` establishes real APT, dpkg, PostgreSQL and systemd
behaviour.
"""

import re
import shlex
from contextlib import nullcontext
from pathlib import Path
from typing import ClassVar, override
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase

from discovery.models import DiscoveryAttempt
from discovery.ssh import CommandResult
from operations.models import RemoteOperation

from . import apply, profiles, releases
from .fakes import RESOLUTE_PACKAGING, Packaging
from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
    Verification,
)
from .native import Exit
from .test_apply import ApplyTestCase

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
EVERY_ADDRESS = "0.0.0.0"  # noqa: S104 - an address ss reports, not a bind
MAJOR = {"24.04": "16", "26.04": "18"}


class PostgreSQLProfileTests(SimpleTestCase):
    def test_each_release_installs_its_default_major_and_main_cluster(self) -> None:
        for release, major in ((releases.NOBLE, "16"), (releases.RESOLUTE, "18")):
            with self.subTest(release=release.version):
                profile = profiles.profile(release, Action.POSTGRESQL)
                self.assertEqual(profile.roots, (f"postgresql-{major}",))
                self.assertEqual(
                    profile.units, ("postgresql.service", f"postgresql@{major}-main.service")
                )
                # The umbrella unit's active (exited) state proves nothing; the cluster runs.
                self.assertEqual(profile.serving_unit, f"postgresql@{major}-main.service")
                self.assertEqual(profile.components, ("main",))
                self.assertEqual(profile.socket, "/var/run/postgresql/.s.PGSQL.5432")
                self.assertEqual(profile.addresses, {"127.0.0.1", "[::1]"})
                self.assertTrue(profile.exclusive and profile.readiness)
                self.assertIn(f"/var/lib/postgresql/{major}/main", profile.revalidation)
                # A data root's dot files are not data; /etc/postgresql's names all count.
                self.assertIn(
                    f"find /var/lib/postgresql /var/lib/postgresql/{major} -mindepth 1 "
                    "-maxdepth 1 ! -name '.*'",
                    profile.revalidation,
                )
                self.assertIn(
                    f"find /etc/postgresql /etc/postgresql/{major} -mindepth 1 -maxdepth 1 -printf",
                    profile.revalidation,
                )
                # Only root and postgres read the cluster's authentication files.
                self.assertIn(
                    f"stat -c '%s %Y %n' -- /etc/postgresql/{major}/main/", profile.revalidation
                )
                check = profile.check
                self.assertEqual(
                    check.argv[:5], ("/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql")
                )
                self.assertEqual(
                    (check.expected or "").splitlines()[:2],
                    [
                        (
                            f"postgres|{major}|/var/lib/postgresql/{major}/main|"
                            f"/etc/postgresql/{major}/main/pg_hba.conf|localhost|scram-sha-256|5432|"
                            "/var/run/postgresql|t|0|f|t"
                        ),
                        "local|{all}|{postgres}|peer",
                    ],
                )
                self.assertIn("pg_file_settings", check.argv[-3])
                self.assertIn("pending_restart", check.argv[-3])
                self.assertIn("pg_conf_load_time()", check.argv[-3])
                self.assertFalse(profile.startable)
        self.assertEqual(
            profiles.profile(releases.NOBLE, Action.POSTGRESQL).intent,
            "Install the distribution-default PostgreSQL 16 server and its main cluster from "
            "Ubuntu 24.04 packages.",
        )

    def test_the_documented_sudoers_rule_is_the_check_escaped(self) -> None:
        docs = (Path(settings.BASE_DIR) / "docs" / "bootstrap.md").read_text(encoding="utf-8")
        for release in (releases.NOBLE, releases.RESOLUTE):
            check = profiles.profile(release, Action.POSTGRESQL).check
            self.assertIn(f"deploy ALL=(root) NOPASSWD: {check.sudoers}", docs)

    def test_locale_dependent_settings_are_left_out_of_the_comparison(self) -> None:
        profile = profiles.profile(releases.NOBLE, Action.POSTGRESQL)
        shown = (
            f"{profile.defaults.expected if profile.defaults else ''}\n"
            "lc_messages = 'de_DE.UTF-8'\ntimezone = 'Europe/Berlin'  \n"
        )
        self.assertEqual(profile.effective(shown), profile.defaults and profile.defaults.expected)
        self.assertNotEqual(profile.effective(shown + "shared_buffers = 1GB\n"), shown)


class PostgreSQLTestCase(ApplyTestCase):
    """A simulated server of ``packaging``'s release without PostgreSQL unless a test
    installs it."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd.on_submit = self.postgresql_installed

    @property
    def major(self) -> str:
        return MAJOR[self.packaging.release.version]

    def postgresql_installed(self) -> None:
        if self.systemd.exit_status == 0:
            self.ubuntu.postgresql = "installed"
            self.ubuntu.postgresql_active = "active"
            self.ubuntu.postgresql_enabled = "enabled"
            self.ubuntu.answer(self.remote)

    def postgresql_plan(self) -> ConfigurationPlan:
        plan = self.plan("postgresql")
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def refused(self, *reasons: str) -> ConfigurationPlan:
        plan = self.plan("postgresql")
        self.assertFalse(plan.eligible)
        self.assertEqual(set(self.reasons(plan)), set(reasons), self.texts(plan))
        return plan

    def texts(self, plan: ConfigurationPlan) -> list[str]:
        return list(plan.refusals.values_list("text", flat=True))

    def payload(self) -> str:
        (submission,) = self.systemd.submissions
        return shlex.split(submission)[-1]

    def fresh(self) -> None:
        self.fresh_server()
        self.systemd.submissions.clear()
        self.systemd.answer(self.remote)
        ApplyRun.objects.all().delete()
        DiscoveryAttempt.objects.all().delete()


class PostgreSQLReviewTests(PostgreSQLTestCase):
    def test_an_installation_reviews_the_exact_closure_and_its_effects(self) -> None:
        plan = self.postgresql_plan()
        packaging = self.packaging
        major = self.major
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [(f"postgresql-{major}", packaging.postgresql_version, False)],
        )
        installs = list(plan.transitions.filter(step="install").values_list("package", "version"))
        self.assertEqual(installs, [(n, v) for n, v, _, _ in packaging.postgresql_packages])
        effects = dict(plan.effects.values_list("kind", "text"))
        self.assertEqual(
            list(effects),
            [
                Effect.PACKAGES,
                Effect.PACKAGE_GUARD,
                Effect.MAINTAINER_START,
                Effect.DATA_DIRECTORY,
                Effect.DATABASE_LISTENERS,
                Effect.NEEDRESTART,
                Effect.NO_ROLLBACK,
            ],
        )
        self.assertIn("pg_createcluster", effects[Effect.DATA_DIRECTORY])
        self.assertIn("follow the server's own", effects[Effect.DATA_DIRECTORY])
        self.assertIn("127.0.0.1 and ::1 only", effects[Effect.DATABASE_LISTENERS])
        postconditions = " ".join(plan.postconditions.values_list("text", flat=True))
        self.assertIn(f"postgresql@{major}-main.service is running", postconditions)
        self.assertNotIn(
            PlanEvidence.Kind.ADMINISTRATION, set(plan.evidence.values_list("kind", flat=True))
        )
        self.assertContains(self.client.get(f"/servers/{self.server.pk}/"), "PostgreSQL profile")

    def test_an_established_cluster_is_a_no_op_only_when_its_administration_is_proven(
        self,
    ) -> None:
        for privilege in ("sudo", "root"):
            with self.subTest(privilege=privilege):
                self.fresh()
                self.ubuntu.postgresql = "installed"
                self.ubuntu.privilege = privilege
                self.systemd.root = privilege == "root"
                plan = self.plan("postgresql")
                self.assertTrue(plan.eligible and plan.no_changes, self.texts(plan))
                evidence = plan.evidence.get(kind=PlanEvidence.Kind.ADMINISTRATION)
                self.assertEqual(evidence.summary, "The administrative check ran with privilege.")
                self.assertFalse([c for c in self.remote.commands if "apt-get -s" in c])

    def test_unverified_or_custom_administration_is_refused(self) -> None:
        check = profiles.profile(self.packaging.release, Action.POSTGRESQL).check
        expected = check.expected or ""
        for case, output in (
            ("trust", expected.replace("local|{all}|{all}|peer", "local|{all}|{all}|trust")),
            ("listeners", expected.replace("|localhost|", "|*|")),
            ("password", expected.replace("|t|0|f|t", "|f|0|f|t")),
            ("alter system", expected.replace("|t|0|f|t", "|t|1|t|t")),
            ("unreloaded", expected.replace("|t|0|f|t", "|t|0|f|f")),
        ):
            with self.subTest(case=case):
                self.fresh()
                self.ubuntu.postgresql = "installed"
                self.ubuntu.postgresql_admin = output
                plan = self.refused(Reason.ADMINISTRATION)
                self.assertEqual(
                    self.texts(plan),
                    [
                        (
                            f"The distribution's PostgreSQL {self.major} main cluster is "
                            "installed, but its administration is not the distribution's: as "
                            "postgres, through the local socket, the cluster does not report the "
                            "distribution's data directory, listeners, password encryption and "
                            "password-less postgres role, its authentication rules are not exactly "
                            "the distribution's pg_hba.conf, or the running server does not use "
                            "exactly the configuration under /etc/postgresql, such as after ALTER "
                            "SYSTEM, a change waiting for a restart, or an edited file not yet "
                            "reloaded. Bootstrap does not adopt custom configuration or "
                            "authentication; restore it through ordinary administration, reload or "
                            "restart the cluster, then prepare again."
                        )
                    ],
                )
        self.fresh()
        self.ubuntu.postgresql = "installed"
        self.ubuntu.extra = {f"sudo -n -l {check.command}": CommandResult(1, "")}
        plan = self.refused(Reason.ADMINISTRATION)
        self.assertIn("readiness is unverified", " ".join(self.texts(plan)))

    def test_a_stopped_cluster_is_refused_rather_than_started(self) -> None:
        self.ubuntu.postgresql = "installed"
        self.ubuntu.postgresql_active = "inactive"
        plan = self.refused(Reason.SERVICE_UNIT)
        major = self.major
        self.assertIn(
            f"postgresql@{major}-main.service is not active and enabled (inactive, "
            "enabled-runtime). Bootstrap establishes only a running cluster, whose "
            "administration it can check, and never starts one it did not create, which may "
            "be partly initialized. Start the cluster through ordinary administration, such as "
            f"sudo pg_ctlcluster {major} main start, then prepare again.",
            self.texts(plan),
        )
        self.assertFalse(plan.effects.filter(kind=Effect.SERVICE_START).exists())

    def test_an_ipv4_only_cluster_and_dot_files_are_the_distribution_s(self) -> None:
        # A server without IPv6 on its loopback: localhost is 127.0.0.1 alone.
        self.ubuntu.postgresql = "installed"
        self.ubuntu.postgresql_addresses = ("127.0.0.1",)
        self.ubuntu.postgresql_entries = {"/var/lib/postgresql": (".psql_history", ".bash_history")}
        plan = self.plan("postgresql")
        self.assertTrue(plan.eligible and plan.no_changes, self.texts(plan))

    def test_a_cluster_installed_from_another_archive_is_not_adopted(self) -> None:
        self.ubuntu.postgresql = "installed"
        version = f"{self.major}.9-1.pgdg24.04+1"
        self.ubuntu.installed_versions = {f"postgresql-{self.major}": version}
        text = " ".join(self.texts(self.refused(Reason.PACKAGE_SOURCE)))
        self.assertIn(f"postgresql-{self.major} {version} is installed, but", text)
        self.assertIn("may come from another repository", text)
        self.assertNotIn("--only-upgrade", text)

    def test_a_superseded_release_update_is_refused_with_its_upgrade(self) -> None:
        self.ubuntu.postgresql = "installed"
        package = f"postgresql-{self.major}"
        version = f"{self.major}.1-0ubuntu0.{self.packaging.release.version}.1"
        self.ubuntu.installed_versions = {package: version}
        plan = self.refused(Reason.PACKAGE_SOURCE)
        self.assertIn(
            f"{package} {version} is installed, but it is no longer offered by "
            f"{self.packaging.release.name}'s archive, which offers "
            f"{self.packaging.postgresql_version}. Upgrade it with ordinary administration, "
            f"such as sudo apt-get install --only-upgrade {package}, then prepare again.",
            self.texts(plan),
        )

    def test_extra_clusters_other_majors_remnants_and_custom_settings_are_refused(self) -> None:
        major = self.major
        other = "15"
        absent: list[tuple[dict[str, object], tuple[str, ...], str]] = [
            ({"postgresql": "leftover"}, (Reason.LEFTOVER,), f"postgresql-{major} was removed"),
            (
                {"data_paths": {"/var/lib/postgresql": "directory postgres"}},
                (Reason.LEFTOVER,),
                "/var/lib/postgresql",
            ),
            (
                {"postgresql_releases": ((f"postgresql-{other}", f"{other}.9-1", "ii"),)},
                (Reason.UNSUPPORTED_VERSION,),
                f"postgresql-{other}",
            ),
            ({"database_listeners": ("127.0.0.1",)}, (Reason.LISTENER,), "port 5432"),
        ]
        installed: list[tuple[dict[str, object], tuple[str, ...], str]] = [
            (
                {"postgresql_entries": {f"/etc/postgresql/{major}": ("reports",)}},
                (Reason.CUSTOMIZED,),
                f"/etc/postgresql/{major}/reports",
            ),
            (
                {"postgresql_entries": {f"/var/lib/postgresql/{major}": ("archive",)}},
                (Reason.LEFTOVER,),
                f"/var/lib/postgresql/{major}/archive",
            ),
            (
                {"postgresql_entries": {"/etc/postgresql": (other,)}},
                (Reason.UNSUPPORTED_VERSION,),
                f"/etc/postgresql/{other}",
            ),
            (
                {"postgresql_entries": {"/var/lib/postgresql": (other, ".psql_history")}},
                (Reason.LEFTOVER,),
                f"/var/lib/postgresql/{other}",
            ),
            (
                {"data_paths": {f"/var/lib/postgresql/{major}/main": ""}},
                (Reason.CUSTOMIZED,),
                "initialized",
            ),
            (
                {"postgresql_addresses": (EVERY_ADDRESS, "[::]")},
                (Reason.LISTENER,),
                "not only at 127.0.0.1",
            ),
            (
                {"postgresql_settings": "listen_addresses = '*'"},
                (Reason.CUSTOMIZED,),
                "pg_conftool",
            ),
            (
                {"extra_files": {f"/etc/postgresql/{major}/main/conf.d/tuning.conf": "1" * 32}},
                (Reason.CUSTOMIZED,),
                "conf.d/tuning.conf",
            ),
            (
                {"changed_conffiles": (f"/etc/postgresql/{major}/main/start.conf",)},
                (Reason.CUSTOMIZED,),
                "start.conf (changed",
            ),
        ]
        for changes, reasons, named in [
            *absent,
            *(({"postgresql": "installed", **c}, r, n) for c, r, n in installed),
        ]:
            with self.subTest(changes=changes):
                self.fresh_server()
                for name, value in changes.items():
                    setattr(self.ubuntu, name, value)
                plan = self.refused(*reasons)
                self.assertTrue(any(named in text for text in self.texts(plan)), self.texts(plan))

    def test_a_changed_authentication_file_is_refused_when_root_reads_it(self) -> None:
        self.ubuntu.postgresql = "installed"
        self.ubuntu.privilege = "root"
        self.systemd.root = True
        self.ubuntu.changed_conffiles = (f"/etc/postgresql/{self.major}/main/pg_hba.conf",)
        plan = self.plan("postgresql")
        self.assertIn(Reason.CUSTOMIZED, self.reasons(plan))
        self.assertIn("pg_hba.conf (changed from what", " ".join(self.texts(plan)))


class PostgreSQLApplyTests(PostgreSQLTestCase):
    def test_a_reviewed_installation_runs_exactly_and_is_verified(self) -> None:
        run = self.apply(self.postgresql_plan())
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual((run.execution, run.verification), (Execution.SUCCEEDED, "passed"))
        payload = self.payload()
        install = re.search(r" install (\S+) 2>&1", payload)
        if install is None:
            self.fail("The payload runs no installation.")
        self.assertEqual(install[1], f"postgresql-{self.major}={self.packaging.postgresql_version}")
        profile = self.packaging.postgresql
        self.assertIn(profile.revalidation, payload)
        self.assertTrue(payload.endswith(f"{profile.check.step()}; exit 0"))
        self.assertIn(f"/usr/bin/pg_conftool {self.major} main show all", self.remote.commands)

    def test_each_postcondition_is_verified_beyond_the_package_and_process(self) -> None:
        cases: tuple[tuple[str, str, dict[str, object]], ...] = (
            ("listener", "_default_listeners", {"postgresql_addresses": (EVERY_ADDRESS,)}),
            (
                "other cluster",
                "_listings_kept",
                {"postgresql_entries": {f"/var/lib/postgresql/{self.major}": ("archive",)}},
            ),
            ("settings", "_configuration_kept", {"postgresql_settings": "port = 5433"}),
            ("runtime", "_runtime_matches", {}),
        )
        for case, checker, change in cases:
            for passing in (False, True):
                with self.subTest(case=case, patched=passing):
                    self.fresh()

                    def installed_differently(
                        change: dict[str, object] = change, case: str = case
                    ) -> None:
                        self.postgresql_installed()
                        for name, value in change.items():
                            setattr(self.ubuntu, name, value)
                        self.ubuntu.answer(self.remote)
                        if case == "runtime":
                            runtime = self.packaging.postgresql.runtime
                            self.remote.results[runtime.command if runtime else ""] = CommandResult(
                                0, "postgres (PostgreSQL) 15.9\n"
                            )

                    self.systemd.on_submit = installed_differently
                    plan = self.postgresql_plan()
                    patch = (
                        mock.patch.object(apply, checker, return_value=True)
                        if passing
                        else nullcontext()
                    )
                    with patch:
                        run = self.apply(plan)
                    self.assertEqual(run.execution, Execution.SUCCEEDED)
                    expected = Verification.PASSED if passing else Verification.FAILED
                    self.assertEqual(run.verification, expected, run.failure)
                    if not passing:
                        self.assertIn("PostgreSQL profile's postconditions", run.failure)

    def test_a_failed_final_check_keeps_the_partial_installation(self) -> None:
        self.systemd.exit_status = Exit.VALIDATION_FAILED
        run = self.apply(self.postgresql_plan())
        self.assertEqual(run.execution, Execution.VALIDATION_FAILED)
        self.assertIn("PostgreSQL main cluster did not show", run.failure)


class ResolutePostgreSQLReviewTests(PostgreSQLReviewTests):
    packaging: ClassVar[Packaging] = RESOLUTE_PACKAGING


class ResolutePostgreSQLApplyTests(PostgreSQLApplyTests):
    packaging: ClassVar[Packaging] = RESOLUTE_PACKAGING
