"""The MariaDB profile's review and apply, per supported release.

Real views, services, the worker, persistence and rendering run against a simulated
Ubuntu server whose packages, units, configuration, data directories, option files,
listeners and administrative check are those recorded on each release's disposable
server. These tests establish what the review admits and refuses and what a run submits
and verifies; ``bootstrap/test_mariadb_remote.py`` establishes real APT, dpkg, MariaDB and
systemd behaviour.
"""

import dataclasses
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

from . import apply, native, profiles, releases
from .evidence import WebEvidence
from .fakes import MARIADB_RUNTIME, RESOLUTE_PACKAGING, THIRD_PARTY, Packaging
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
from .review import Draft, _check_exposure, _check_paths
from .test_apply import ApplyTestCase

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
DATA = {"24.04": "/var/lib/mysql", "26.04": "/var/lib/mariadb"}
EVERY_ADDRESS = "0.0.0.0"  # noqa: S104 - an address ss reports, not a bind
ADMINISTRATOR = (
    "root@localhost\n"
    "CREATE USER `root`@`localhost` IDENTIFIED VIA mysql_native_password USING 'invalid' "
    "OR unix_socket\n0"
)


class MariaDBProfileTests(SimpleTestCase):
    def test_each_release_has_its_own_series_components_and_data_directory(self) -> None:
        noble = profiles.profile(releases.NOBLE, Action.MARIADB)
        resolute = profiles.profile(releases.RESOLUTE, Action.MARIADB)
        self.assertEqual(noble.roots, ("mariadb-server",))
        self.assertEqual(noble.serving_unit, "mariadb.service")
        self.assertEqual((noble.components, resolute.components), (("main", "universe"), ("main",)))
        self.assertEqual(
            noble.intent,
            "Install the distribution MariaDB 10.11 server from Ubuntu 24.04 packages.",
        )
        self.assertIn("MariaDB 11.8", resolute.intent)
        self.assertEqual(noble.check.expected, ADMINISTRATOR)
        self.assertEqual(
            noble.check.argv[:6],
            (
                "/usr/bin/mariadb",
                "--no-defaults",
                "--protocol=socket",
                "--socket=/run/mysqld/mysqld.sock",
                "--user=root",
                "-N",
            ),
        )
        self.assertTrue(noble.readiness)
        self.assertEqual(
            (noble.port, noble.addresses, noble.exclusive), (3306, {"127.0.0.1"}, True)
        )
        for profile, data, foreign in (
            (noble, "/var/lib/mysql", "/var/lib/mariadb"),
            (resolute, "/var/lib/mariadb", "/var/lib/mysql"),
        ):
            with self.subTest(data=data):
                spec = profile.data
                if spec is None:
                    self.fail("The profile has no data directory.")
                self.assertEqual((spec.directory, spec.marker), (data, f"{data}/mysql"))
                self.assertEqual(spec.remnants, ("/var/log/mysql",))
                self.assertIn(foreign, profile.forbidden)
                self.assertIn("/etc/my.cnf", profile.forbidden)
                # Applying rechecks the paths, the alternative and root-only files.
                digest = profile.revalidation
                self.assertIn(f"stat -c '%F %U %n' -- {data} {data}/mysql", digest)
                self.assertIn("sha256sum -- /var/lib/dpkg/alternatives/my.cnf", digest)
                self.assertIn("readlink -f -- /etc/mysql/my.cnf", digest)
                self.assertIn("stat -c '%s %Y %n' -- /etc/mysql/debian.cnf", digest)
                self.assertIn("! -path /etc/mysql/debian.cnf", digest)
        self.assertNotEqual(noble.revalidation, resolute.revalidation)
        self.assertIn("utf8mb4", (noble.defaults and noble.defaults.expected) or "")

    def test_the_final_check_compares_its_exact_output(self) -> None:
        check = profiles.profile(releases.NOBLE, Action.MARIADB).check
        step = check.step()
        self.assertIn(f"c=$({check.command}) || exit 24", step)
        self.assertIn(f'[ "$c" = {shlex.quote(ADMINISTRATOR)} ] || exit 24', step)
        # Each argument is validated before it is quoted into the payload.
        for bad in (("mariadb",), ("/usr/bin/mariadb", "a\nb"), ("/opt/x", "-t")):
            with self.subTest(argv=bad), self.assertRaises(ValueError):
                native.Check(bad).step()
        self.assertEqual(
            profiles.profile(releases.NOBLE, Action.NGINX).check.step(),
            "/usr/sbin/nginx -t -q || exit 24",
        )

    def test_the_documented_sudoers_rule_is_the_check_escaped(self) -> None:
        check = profiles.profile(releases.NOBLE, Action.MARIADB).check
        docs = (Path(settings.BASE_DIR) / "docs" / "bootstrap.md").read_text(encoding="utf-8")
        self.assertIn(f"deploy ALL=(root) NOPASSWD: {check.sudoers}", docs)
        self.assertIn(r"--protocol\=socket", check.sudoers)
        for wildcard in ("*", "?", "[", "]"):
            with self.subTest(wildcard=wildcard), self.assertRaises(ValueError):
                _ = native.Check(("/usr/bin/mariadb", f"-e SELECT {wildcard}")).sudoers

    def test_paths_for_postgresql_style_layouts_are_accepted(self) -> None:
        digest = native.package_digest(
            ("postgresql@16-main.service",),
            ("/etc/postgresql",),
            5432,
            ucf=False,
            socket="/var/run/postgresql/.s.PGSQL.5432",
            paths=("/var/lib/postgresql/16/main", "/var/lib/postgresql/16/main/PG_VERSION"),
        )
        self.assertIn("/var/lib/postgresql/16/main/PG_VERSION", digest)
        for socket in ("/run/../etc/passwd", "/srv/x.sock"):
            with self.subTest(socket=socket), self.assertRaises(ValueError):
                native.package_digest((), ("/etc/x",), None, ucf=False, socket=socket)

    def test_the_stock_profiles_keep_their_definitions(self) -> None:
        nginx = profiles.profile(releases.NOBLE, Action.NGINX)
        php = profiles.profile(releases.NOBLE, Action.PHP)
        self.assertEqual(nginx.components, ("main",))
        self.assertIsNone(nginx.data)
        self.assertFalse(nginx.exclusive or nginx.conflicts or php.conflicts or php.readiness)
        self.assertNotIn("stat -c", nginx.revalidation + php.revalidation)
        self.assertEqual(php.check.command, "/usr/sbin/php-fpm8.3 -t")
        self.assertIn(Action.MARIADB, profiles.PACKAGE_ACTIONS)

    def test_a_data_listing_and_a_file_marker_generalize_the_data_directory(self) -> None:
        mariadb = profiles.profile(releases.NOBLE, Action.MARIADB)
        spec = profiles.DataSpec(
            "/var/lib/postgresql/16/main",
            "postgres",
            "/var/lib/postgresql/16/main/PG_VERSION",
            "regular file",
            "Initializes the cluster.",
            listings=(("/var/lib/postgresql", frozenset({"16"})),),
        )
        profile = dataclasses.replace(mariadb, data=spec, forbidden=())
        self.assertIn("find /var/lib/postgresql -mindepth 1", profile.revalidation)
        web = WebEvidence(
            (),
            (),
            (),
            {},
            None,
            data={
                spec.directory: "directory postgres",
                spec.marker: "regular file postgres",
            },
            layout={"/var/lib/postgresql": ("16", "15")},
        )
        draft = Draft(Action.MARIADB, "", None, None)
        _check_paths(draft, profile, web, installed=True)
        self.assertEqual([reason for reason, _ in draft.refusals], [Reason.LEFTOVER])
        self.assertIn("/var/lib/postgresql/15", draft.refusals[0][1])
        # A serving unit other than the first decides whether the service runs.
        umbrella = dataclasses.replace(
            profile, units=("postgresql.service", "x.service"), serving="x.service"
        )
        self.assertEqual(umbrella.serving_unit, "x.service")
        draft = Draft(Action.MARIADB, "", None, None)
        _check_exposure(draft, umbrella, web, complete=True, serving=True)
        self.assertFalse(draft.refusals)


class MariaDBReviewTestCase(ApplyTestCase):
    """A simulated server of ``packaging``'s release without MariaDB unless a test installs it."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd.on_submit = self.mariadb_installed

    def mariadb_installed(self) -> None:
        if self.systemd.exit_status == 0:
            self.ubuntu.mariadb = "installed"
            self.ubuntu.mariadb_active = "active"
            self.ubuntu.mariadb_enabled = "enabled"
            self.ubuntu.answer(self.remote)

    def mariadb_plan(self) -> ConfigurationPlan:
        plan = self.plan("mariadb")
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def refused(self, *reasons: str) -> ConfigurationPlan:
        plan = self.plan("mariadb")
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


class MariaDBReviewTests(MariaDBReviewTestCase):
    def test_an_installation_reviews_the_exact_closure_and_its_effects(self) -> None:
        plan = self.mariadb_plan()
        packaging = self.packaging
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("mariadb-server", packaging.mariadb_version, False)],
        )
        installs = list(plan.transitions.filter(step="install").values_list("package", "version"))
        self.assertEqual(installs, [(n, v) for n, v, _, _ in packaging.mariadb_packages])
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
        archives = {
            "24.04": "from the Ubuntu 24.04 archives' main and universe components.",
            "26.04": "from the Ubuntu 26.04 archives.",
        }
        self.assertIn(archives[packaging.release.version], effects[Effect.PACKAGES])
        self.assertIn(DATA[packaging.release.version], effects[Effect.DATA_DIRECTORY])
        self.assertIn("never removes, migrates or adopts", effects[Effect.DATA_DIRECTORY])
        self.assertIn("127.0.0.1 only", effects[Effect.DATABASE_LISTENERS])
        self.assertIn("No database, database user, password", effects[Effect.DATABASE_LISTENERS])
        postconditions = " ".join(plan.postconditions.values_list("text", flat=True))
        self.assertIn("as root@localhost, which authenticates by unix_socket", postconditions)
        self.assertIn("/etc/mysql/my.cnf resolves to /etc/mysql/mariadb.cnf", postconditions)
        kinds = set(plan.evidence.values_list("kind", flat=True))
        self.assertLessEqual({PlanEvidence.Kind.LISTENERS, PlanEvidence.Kind.DATA_PATHS}, kinds)
        # Nothing is installed, so nothing ran with privilege.
        self.assertNotIn(PlanEvidence.Kind.ADMINISTRATION, kinds)
        self.assertFalse([c for c in self.remote.commands if "/usr/bin/mariadb " in c])
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "MariaDB profile")

    def test_an_established_engine_is_a_no_op_only_when_its_administration_is_proven(
        self,
    ) -> None:
        self.ubuntu.mariadb = "installed"
        for privilege in ("sudo", "root"):
            with self.subTest(privilege=privilege):
                self.fresh()
                self.ubuntu.mariadb = "installed"
                self.ubuntu.privilege = privilege
                self.systemd.root = privilege == "root"
                plan = self.plan("mariadb")
                self.assertTrue(plan.eligible and plan.no_changes, self.texts(plan))
                evidence = plan.evidence.get(kind=PlanEvidence.Kind.ADMINISTRATION)
                self.assertEqual(evidence.summary, "The administrative check ran with privilege.")
                command = profiles.profile(self.packaging.release, Action.MARIADB).check.command
                expected = command if privilege == "root" else f"sudo -n {command}"
                self.assertIn(expected, self.remote.commands)
                self.assertFalse([c for c in self.remote.commands if "apt-get -s" in c])
        self.request_refused(plan)

    def test_unverified_or_custom_administration_is_refused(self) -> None:
        command = profiles.profile(self.packaging.release, Action.MARIADB).check.command
        for case, change in (
            ("unauthorized", {f"sudo -n -l {command}": CommandResult(1, "")}),
            ("password", {f"sudo -n {command}": CommandResult(1, "")}),
            (
                "anonymous",
                {f"sudo -n {command}": CommandResult(0, ADMINISTRATOR[:-1] + "2\n")},
            ),
            (
                "authentication",
                {
                    f"sudo -n {command}": CommandResult(
                        0, ADMINISTRATOR.replace(" OR unix_socket", "") + "\n"
                    )
                },
            ),
        ):
            with self.subTest(case=case):
                self.fresh()
                self.ubuntu.mariadb = "installed"
                self.ubuntu.extra = change
                plan = self.refused(Reason.ADMINISTRATION)
                self.assertFalse(plan.no_changes)
                if case == "unauthorized":
                    self.assertIn("readiness is unverified", " ".join(self.texts(plan)))
                else:
                    self.assertEqual(
                        self.texts(plan),
                        [
                            (
                                "The distribution's MariaDB server is installed, but its "
                                "administration is not the distribution's: as root, without a "
                                "password or option files, the local socket does not connect as "
                                "root@localhost authenticated only by unix_socket, or anonymous or "
                                "remote root accounts exist. Bootstrap does not adopt custom "
                                "authentication; restore it through ordinary administration, then "
                                "prepare again."
                            )
                        ],
                    )
        # Without root or sudo, preparation is refused before it reads with privilege.
        self.fresh()
        self.ubuntu.mariadb = "installed"
        self.ubuntu.privilege = "none"
        plan = self.plan("mariadb")
        self.assertIn(Reason.ADMINISTRATION, self.reasons(plan))
        self.assertNotIn(command, self.remote.commands)

    def request_refused(self, plan: ConfigurationPlan) -> None:
        self.sign_in_with(
            "view_server",
            "view_configurationplan",
            "prepare_configurationplan",
            "apply_configurationplan",
        )
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertFalse(ApplyRun.objects.filter(plan_number=plan.pk).exists())

    def test_a_stopped_disabled_engine_proposes_enable_and_start(self) -> None:
        self.ubuntu.mariadb = "installed"
        self.ubuntu.mariadb_active = "inactive"
        self.ubuntu.mariadb_enabled = "disabled"
        plan = self.mariadb_plan()
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [Effect.SERVICE_ENABLE, Effect.SERVICE_START, Effect.DATABASE_LISTENERS],
        )
        evidence = plan.evidence.get(kind=PlanEvidence.Kind.ADMINISTRATION)
        self.assertIn("applying checks administration", evidence.summary)

    def test_conflicting_installations_and_remnants_are_refused(self) -> None:
        release = self.packaging.release.version
        data = DATA[release]
        other = DATA["26.04" if release == "24.04" else "24.04"]
        cases: list[tuple[dict[str, object], tuple[str, ...], str]] = [
            (
                {"database_conflicts": (("mysql-server-8.0", "8.0.46-0ubuntu0.24.04.4", "ii"),)},
                (Reason.CONFLICT,),
                "mysql-server-8.0 8.0.46",
            ),
            (
                {"database_conflicts": (("mysql-server-8.0", "8.0.46-0ubuntu0.24.04.4", "rc"),)},
                (Reason.CONFLICT,),
                "mysql-server-8.0 (configuration files left)",
            ),
            (
                {"database_conflicts": (("default-mysql-server", "1.1.0build1", "ii"),)},
                (Reason.CONFLICT,),
                "default-mysql-server",
            ),
            # A purged server whose data directory or logs stayed.
            ({"data_paths": {data: "directory mysql"}}, (Reason.LEFTOVER,), data),
            (
                {"data_paths": {"/var/log/mysql": "directory mysql"}},
                (Reason.LEFTOVER,),
                "/var/log/mysql",
            ),
            # A dangling link is not absence.
            ({"data_paths": {data: "symbolic link root"}}, (Reason.LEFTOVER,), data),
            (
                {"data_paths": {"/var/lib/mysql-files": "directory mysql"}},
                (Reason.LEFTOVER,),
                "mysql-files",
            ),
            (
                {"data_paths": {"/etc/my.cnf": "regular file root"}},
                (Reason.LEFTOVER,),
                "/etc/my.cnf",
            ),
            # A manually set my.cnf alternative before installation.
            (
                {"mariadb_alternative": "manual", "mariadb_alternative_value": "/root/my.cnf"},
                (Reason.CUSTOMIZED,),
                "set manually to /root/my.cnf",
            ),
            ({"mariadb": "leftover"}, (Reason.LEFTOVER,), "mariadb-server was removed"),
            ({"database_listeners": (EVERY_ADDRESS,)}, (Reason.LISTENER,), "port 3306 (0.0.0.0)"),
        ]
        installed: list[tuple[dict[str, object], tuple[str, ...], str]] = [
            ({"data_paths": {other: "directory mysql"}}, (Reason.LEFTOVER,), other),
            ({"data_paths": {f"{data}/mysql": ""}}, (Reason.CUSTOMIZED,), "initialized"),
            ({"data_paths": {data: "symbolic link root"}}, (Reason.CUSTOMIZED,), "initialized"),
            ({"mariadb_addresses": (EVERY_ADDRESS,)}, (Reason.LISTENER,), "not only at 127.0.0.1"),
            ({"mariadb_addresses": ("127.0.0.1", "[::1]")}, (Reason.LISTENER,), "[::1]"),
            (
                {"changed_conffiles": ("/etc/mysql/mariadb.conf.d/50-server.cnf",)},
                (Reason.CUSTOMIZED,),
                "50-server.cnf (changed",
            ),
            (
                {"extra_files": {"/etc/mysql/conf.d/auth.cnf": "1" * 32}},
                (Reason.CUSTOMIZED,),
                "/etc/mysql/conf.d/auth.cnf",
            ),
            # The alternative pointed elsewhere, or option files the review does not see.
            (
                {"mariadb_alternative": "manual", "mariadb_alternative_value": "/root/my.cnf"},
                (Reason.CUSTOMIZED,),
                "resolves to /root/my.cnf",
            ),
            (
                {"mariadb_defaults": "--socket=/run/mysqld/mysqld.sock --skip-grant-tables"},
                (Reason.CUSTOMIZED,),
                "--print-defaults does not report",
            ),
            (
                {"unit_drop_ins": "/etc/systemd/system/mariadb.service.d/override.conf"},
                (Reason.SERVICE_UNIT,),
                "drop-in",
            ),
        ]
        for changes, reasons, named in [
            *cases,
            *(({"mariadb": "installed", **c}, r, n) for c, r, n in installed),
        ]:
            with self.subTest(changes=changes):
                self.fresh_server()
                for name, value in changes.items():
                    setattr(self.ubuntu, name, value)
                plan = self.refused(*reasons)
                self.assertTrue(any(named in text for text in self.texts(plan)), self.texts(plan))

    def test_a_changed_maintainer_generated_file_is_refused_when_readable(self) -> None:
        self.ubuntu.mariadb = "installed"
        self.ubuntu.privilege = "root"
        self.systemd.root = True
        self.ubuntu.changed_conffiles = ("/etc/mysql/debian.cnf",)
        plan = self.refused(Reason.CUSTOMIZED)
        self.assertIn("debian.cnf (changed from what", " ".join(self.texts(plan)))

    def test_an_engine_installed_from_another_archive_is_not_adopted(self) -> None:
        self.ubuntu.mariadb = "installed"
        self.ubuntu.installed_versions = {"mariadb-server": "1:11.4.9+maria~ubu2404"}
        plan = self.refused(Reason.PACKAGE_SOURCE)
        text = " ".join(self.texts(plan))
        self.assertIn("mariadb-server 1:11.4.9+maria~ubu2404 is installed, but", text)
        self.assertIn("may come from another repository", text)
        self.assertNotIn("--only-upgrade", text)

    def test_an_older_version_from_another_archive_is_not_called_superseded(self) -> None:
        self.ubuntu.mariadb = "installed"
        self.ubuntu.installed_versions = {"mariadb-server": "1:10.6.0+maria~ubu2404"}
        text = " ".join(self.texts(self.refused(Reason.PACKAGE_SOURCE)))
        self.assertIn("may come from another repository", text)
        self.assertNotIn("--only-upgrade", text)

    def test_a_superseded_release_update_is_refused_with_its_upgrade(self) -> None:
        self.ubuntu.mariadb = "installed"
        self.ubuntu.installed_versions = {"mariadb-server": "1:10.6.0-1ubuntu0.1"}
        plan = self.refused(Reason.PACKAGE_SOURCE)
        packaging = self.ubuntu.packaging
        expected = (
            "mariadb-server 1:10.6.0-1ubuntu0.1 is installed, but it is no longer offered by "
            f"{packaging.release.name}'s archive, which offers {packaging.mariadb_version}. "
            "Upgrade it with ordinary administration, such as sudo apt-get install "
            "--only-upgrade mariadb-server, then prepare again."
        )
        self.assertEqual(
            [expected],
            [text for text in self.texts(plan) if "mariadb-server 1:10.6.0" in text],
        )

    def test_a_third_party_offer_of_a_closure_package_is_refused(self) -> None:
        self.ubuntu.third_party = True
        self.ubuntu.third_party_offers = (("mariadb-server", "1:11.4.9+maria~ubu2404"),)
        plan = self.refused(Reason.PACKAGE_SOURCE)
        self.assertIn(THIRD_PARTY, " ".join(self.texts(plan)))


class NobleMariaDBTests(MariaDBReviewTestCase):
    def test_the_universe_component_is_required_on_noble(self) -> None:
        self.ubuntu.components = ("main",)
        plan = self.refused(Reason.PACKAGE_METADATA)
        self.assertIn("noble-updates universe", " ".join(self.texts(plan)))
        # Nginx needs main alone.
        self.assertTrue(self.plan("nginx").eligible)

    def test_a_package_only_offered_by_another_component_is_refused(self) -> None:
        # The release's archive offers galera-4 only from multiverse.
        self.ubuntu.components = ("main", "universe", "multiverse")
        self.ubuntu.component_offers = {"galera-4": "multiverse"}
        plan = self.refused(Reason.PACKAGE_SOURCE)
        self.assertIn("only from its multiverse component", " ".join(self.texts(plan)))


class MariaDBApplyTests(MariaDBReviewTestCase):
    def test_a_reviewed_installation_runs_exactly_and_is_verified(self) -> None:
        plan = self.mariadb_plan()
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual((run.execution, run.verification), (Execution.SUCCEEDED, "passed"))
        payload = self.payload()
        install = re.search(r" install (\S+) 2>&1", payload)
        if install is None:
            self.fail("The payload runs no installation.")
        self.assertEqual(install[1], f"mariadb-server={self.packaging.mariadb_version}")
        self.assertIn(self.packaging.mariadb.revalidation, payload)
        check = self.packaging.mariadb.check
        self.assertTrue(payload.endswith(f"{check.step()}; exit 0"))
        commands = self.remote.commands
        self.assertIn(MARIADB_RUNTIME, commands)
        self.assertIn("/usr/sbin/mariadbd --print-defaults", commands)
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)
        self.assertNotIn("password", run.reviewed_changes)

    def test_a_stopped_engine_is_started_without_apt(self) -> None:
        self.ubuntu.mariadb = "installed"
        self.ubuntu.mariadb_active = "inactive"
        run = self.apply(self.mariadb_plan())
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        payload = self.payload()
        self.assertNotIn("apt-get -q -y", payload)
        check = self.packaging.mariadb.check
        self.assertIn(f"systemctl start mariadb.service || exit 22; {check.step()}", payload)

    def test_each_postcondition_is_verified_beyond_the_package_and_process(self) -> None:
        data = DATA[self.packaging.release.version]
        cases: tuple[tuple[str, str, dict[str, object]], ...] = (
            ("listener", "_default_listeners", {"mariadb_addresses": (EVERY_ADDRESS,)}),
            ("data", "_data_initialized", {"data_paths": {f"{data}/mysql": ""}}),
            (
                "option file",
                "_configuration_kept",
                {"data_paths": {"/etc/my.cnf": "regular file root"}},
            ),
            ("defaults", "_configuration_kept", {"mariadb_defaults": "--skip-networking"}),
            ("runtime", "_runtime_matches", {}),
        )
        for case, checker, change in cases:
            for passing in (False, True):
                with self.subTest(case=case, patched=passing):
                    self.fresh()

                    def installed_differently(
                        change: dict[str, object] = change, case: str = case
                    ) -> None:
                        self.mariadb_installed()
                        for name, value in change.items():
                            setattr(self.ubuntu, name, value)
                        self.ubuntu.answer(self.remote)
                        if case == "runtime":
                            self.remote.results[MARIADB_RUNTIME] = CommandResult(
                                0, "/usr/sbin/mariadbd  Ver 10.6.18-MariaDB for debian-linux-gnu\n"
                            )

                    self.systemd.on_submit = installed_differently
                    plan = self.mariadb_plan()
                    # Only this postcondition fails: with it held, the run verifies.
                    with (
                        mock.patch.object(apply, checker, return_value=True)
                        if passing
                        else nullcontext()
                    ):
                        run = self.apply(plan)
                    self.assertEqual(run.execution, Execution.SUCCEEDED)
                    expected = Verification.PASSED if passing else Verification.FAILED
                    self.assertEqual(run.verification, expected, run.failure)
                    if not passing:
                        self.assertIn("MariaDB profile's postconditions", run.failure)

    def test_a_failed_final_check_keeps_the_partial_installation(self) -> None:
        self.systemd.exit_status = Exit.VALIDATION_FAILED
        run = self.apply(self.mariadb_plan())
        self.assertEqual(run.execution, Execution.VALIDATION_FAILED)
        self.assertIn("did not show the distribution's local administration", run.failure)
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)


class ResoluteMariaDBReviewTests(MariaDBReviewTests):
    packaging: ClassVar[Packaging] = RESOLUTE_PACKAGING


class ResoluteMariaDBApplyTests(MariaDBApplyTests):
    packaging: ClassVar[Packaging] = RESOLUTE_PACKAGING
