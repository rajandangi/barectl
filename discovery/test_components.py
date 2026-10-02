"""Web-stack component observations, tested through ``collect``."""

from typing import Literal

from . import ssh
from .fakes import (
    CLUSTER_UNITS,
    DPKG_OUTPUT,
    MAIN_UNIT,
    PACKAGE_QUERY,
    PG_DIR,
    UMBRELLA_REPORT,
    UMBRELLA_UNIT,
    UNIT_QUERY,
    ObservationTestCase,
    cluster_conf,
    cluster_report,
    unit_report,
)
from .models import WebStackComponent
from .snapshot import CollectedSnapshot, Package, ServiceUnit, WebStackComponentObservation


class ServiceTests(ObservationTestCase):
    def assert_statuses(
        self, collected: CollectedSnapshot, part: Literal["package", "service"], status: str
    ) -> None:
        """Assert every component's ``part`` observation has ``status``, in display order."""
        self.assertEqual(
            [
                (
                    observation.component,
                    (observation.package if part == "package" else observation.service).outcome,
                )
                for observation in collected.components
            ],
            [(component, status) for component in WebStackComponent.values],
        )

    def test_service_stack_is_collected_with_versions_states_and_provenance(self) -> None:
        collected = self.collect()
        self.assertEqual(
            [observation.component for observation in collected.components],
            ["nginx", "php-fpm", "mariadb", "postgresql", "certbot"],
        )
        nginx = self.component("nginx")
        self.assertEqual(nginx.package.outcome, "observed")
        self.assertEqual(nginx.package.value, (Package("nginx", "1.24.0-2ubuntu7.18"),))
        self.assertEqual(nginx.package.source, (PACKAGE_QUERY,))
        self.assertEqual(nginx.service.outcome, "observed")
        self.assertEqual(
            nginx.service.value,
            (ServiceUnit("nginx.service", "loaded", "active", "running", "enabled"),),
        )
        self.assertEqual(nginx.service.source, (UNIT_QUERY.format("nginx.service"),))
        php = self.component("php-fpm")
        self.assertEqual(php.package.value, (Package("php8.3-fpm", "8.3.6-0ubuntu0.24.04.11"),))
        self.assertEqual(
            php.service.value,
            (ServiceUnit("php8.3-fpm.service", "loaded", "active", "running", "enabled"),),
        )
        mariadb = self.component("mariadb")
        self.assertIn(
            Package("mariadb-server", "1:10.11.14-0ubuntu0.24.04.1"), mariadb.package.value
        )
        self.assertEqual(
            mariadb.service.value,
            (ServiceUnit("mariadb.service", "loaded", "active", "running", "enabled"),),
        )
        postgres = self.component("postgresql")
        self.assertIn(Package("postgresql-16", "16.15-0ubuntu0.24.04.1"), postgres.package.value)
        self.assertEqual(postgres.service.value, (UMBRELLA_UNIT, MAIN_UNIT))
        # Packages known to apt but not installed, such as the php-fpm metapackage, are not
        # reported as installed.
        self.assertEqual(
            [
                package.name
                for component in collected.components
                for package in component.package.value
            ],
            [
                "nginx",
                "php8.3-fpm",
                "mariadb-server",
                "mariadb-server-core",
                "postgresql",
                "postgresql-16",
                "certbot",
            ],
        )
        self.assert_not_kept("postgresql-16-jit-llvm")

    def test_absent_packages_are_absent_and_skip_service_queries(self) -> None:
        # dpkg-query exits 1 when no pattern matches; nothing is installed.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, "")
        collected = self.collect()
        self.assertEqual(
            [(c.component, c.package.outcome, c.service.outcome) for c in collected.components],
            [
                ("nginx", "absent", "absent"),
                ("php-fpm", "absent", "absent"),
                ("mariadb", "absent", "absent"),
                ("postgresql", "absent", "absent"),
                ("certbot", "absent", "absent"),
            ],
        )
        self.assertEqual([c.service.value for c in collected.components], [()] * 5)
        self.assertFalse([c for c in self.remote.commands if "systemctl" in c])
        self.assertEqual(self.component("nginx").service.source, (PACKAGE_QUERY,))
        self.assertEqual(
            self.component("nginx").package.warning,
            "The dpkg database lists no installed Nginx packages.",
        )

    def test_known_but_uninstalled_packages_are_not_reported(self) -> None:
        # dpkg-query lists packages apt knows about with a status other than "ii".
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            1, "nginx  un \nphp8.3-fpm  un \nmariadb-server  rc \n"
        )
        collected = self.collect()
        self.assert_statuses(collected, "package", "absent")

    def test_missing_dpkg_query_is_unsupported_not_absent(self) -> None:
        # POSIX shells exit 127 for a missing command: no dpkg database, no verdict.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(127, "")
        collected = self.collect()
        self.assert_statuses(collected, "package", "unsupported")
        self.assertFalse([c for c in self.remote.commands if "systemctl" in c])
        self.assertEqual(self.component("nginx").service.source, (PACKAGE_QUERY,))
        for component in collected.components:
            with self.subTest(component=component.component):
                self.assertIn(
                    "cannot inspect other installation formats.", component.package.warning
                )
        # Both sub-observations of every component carry the warning, and so do the site
        # file and pool observations that depend on them.
        self.assertEqual(
            self.warned(),
            [
                ("Nginx packages", "unsupported"),
                ("Nginx service units", "unsupported"),
                ("PHP-FPM packages", "unsupported"),
                ("PHP-FPM service units", "unsupported"),
                ("MariaDB packages", "unsupported"),
                ("MariaDB service units", "unsupported"),
                ("PostgreSQL packages", "unsupported"),
                ("PostgreSQL service units", "unsupported"),
                ("Certbot packages", "unsupported"),
                ("Certbot service units", "unsupported"),
                ("Nginx site files", "unsupported"),
                ("PHP-FPM pools", "unsupported"),
            ],
        )

    def test_unrunnable_dpkg_query_is_inaccessible(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(126, "")
        collected = self.collect()
        self.assert_statuses(collected, "package", "inaccessible")
        self.assertEqual(
            self.component("nginx").package.warning,
            "The SSH user cannot run dpkg-query. Barectl does not use sudo.",
        )

    def test_unexpected_dpkg_query_failure_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(2, "")
        collected = self.collect()
        self.assert_statuses(collected, "package", "unsupported")

    def test_unparsable_package_output_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, "nginx 1.24 stuff\ngarbage\n")
        collected = self.collect()
        self.assert_statuses(collected, "package", "unsupported")
        self.assert_not_kept("1.24 stuff", "garbage")

    def test_truncated_package_output_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, DPKG_OUTPUT, truncated=True)
        collected = self.collect()
        self.assert_statuses(collected, "package", "unsupported")
        self.assertEqual(
            self.component("nginx").package.warning,
            f"{PACKAGE_QUERY} wrote more output than expected. It was not read.",
        )

    def test_unavailable_systemd_is_unsupported_not_absent(self) -> None:
        # Containers and minimal servers run without systemd or its bus: exit 1.
        self.remote.results[UNIT_QUERY.format("nginx.service")] = ssh.CommandResult(1, "")
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(
            (nginx.package.outcome, nginx.service.outcome), ("observed", "unsupported")
        )
        self.assertEqual(nginx.service.value, ())
        self.assertEqual(nginx.package.value, (Package("nginx", "1.24.0-2ubuntu7.18"),))
        self.assertIn("could not read service states from systemd.", nginx.service.warning)

    def test_missing_systemctl_is_unsupported(self) -> None:
        self.remote.results = {
            key: (ssh.CommandResult(127, "") if key.startswith("systemctl") else value)
            for key, value in self.remote.results.items()
        }
        collected = self.collect()
        self.assert_statuses(collected, "service", "unsupported")
        for component in collected.components:
            with self.subTest(component=component.component):
                self.assertIn("has no systemctl command", component.service.warning)

    def test_unrunnable_systemctl_is_inaccessible(self) -> None:
        self.remote.results[UNIT_QUERY.format("nginx.service")] = ssh.CommandResult(126, "")
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(nginx.service.outcome, "inaccessible")
        self.assertEqual(
            nginx.service.warning, "The SSH user cannot run systemctl. Barectl does not use sudo."
        )

    def test_stopped_service_is_observed_not_absent(self) -> None:
        # Installed but stopped: the unit is loaded, enabled and inactive.
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0, unit_report("mariadb.service", active="inactive", sub="dead")
        )
        self.collect()
        mariadb = self.component("mariadb")
        self.assertEqual(mariadb.service.outcome, "observed")
        self.assertEqual(
            mariadb.service.value,
            (ServiceUnit("mariadb.service", "loaded", "inactive", "dead", "enabled"),),
        )

    def test_certbot_timer_state_is_observed(self) -> None:
        self.remote.install_certbot(active="inactive", sub="dead", file_state="disabled")
        self.collect()
        certbot = self.component("certbot")
        self.assertEqual(certbot.package.value, (Package("certbot", "2.9.0-1ubuntu1"),))
        self.assertEqual(
            certbot.service.value,
            (ServiceUnit("certbot.timer", "loaded", "inactive", "dead", "disabled"),),
        )
        self.assertEqual(certbot.service.source, (UNIT_QUERY.format("certbot.timer"),))

    def test_an_uninstalled_certbot_is_absent_without_a_unit_query(self) -> None:
        self.remote.commands.clear()
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            1, DPKG_OUTPUT.replace("certbot 2.9.0-1ubuntu1 ii\n", "")
        )
        collected = self.collect()
        certbot = next(c for c in collected.components if c.component == "certbot")
        self.assertEqual((certbot.package.outcome, certbot.service.outcome), ("absent", "absent"))
        self.assertFalse([c for c in self.remote.commands if "certbot.timer" in c])

    def test_unit_without_a_service_file_is_reported_as_not_found(self) -> None:
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0,
            "Id=mariadb.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            "UnitFileState=\n",
        )
        self.collect()
        mariadb = self.component("mariadb")
        self.assertEqual(mariadb.service.outcome, "observed")
        self.assertEqual(
            mariadb.service.value,
            (ServiceUnit("mariadb.service", "not-found", "inactive", "dead", ""),),
        )

    def test_unparsable_unit_output_is_unsupported(self) -> None:
        self.remote.results[UNIT_QUERY.format("nginx.service")] = ssh.CommandResult(
            0, "Id=nginx.service\nActiveState=someting-new\n"
        )
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(nginx.service.outcome, "unsupported")
        # The server-reported unit name is remote data and is never quoted back.
        self.assert_not_kept("someting-new")
        self.assertEqual(
            nginx.service.warning,
            "systemctl did not report a service unit in a supported format.",
        )

    def test_unit_reported_under_another_name_is_unsupported(self) -> None:
        # An alias resolves to its target unit, which is not the documented unit.
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0, unit_report("mysql.service")
        )
        self.collect()
        mariadb = self.component("mariadb")
        self.assertEqual((mariadb.service.outcome, mariadb.service.value), ("unsupported", ()))
        self.assert_not_kept("mysql.service")

    def test_held_and_reinstall_required_packages_are_installed(self) -> None:
        # "hi" is installed and held by apt-mark; "R" flags a package needing reinstallation.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            0,
            DPKG_OUTPUT.replace(
                "nginx 1.24.0-2ubuntu7.18 ii", "nginx 1.24.0-2ubuntu7.18 hi"
            ).replace(
                "php8.3-fpm 8.3.6-0ubuntu0.24.04.11 ii", "php8.3-fpm 8.3.6-0ubuntu0.24.04.11 iiR"
            ),
        )
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(
            (nginx.package.outcome, nginx.package.value),
            ("observed", (Package("nginx", "1.24.0-2ubuntu7.18"),)),
        )
        self.assertEqual(nginx.service.outcome, "observed")
        self.assertEqual(
            self.component("php-fpm").package.value,
            (Package("php8.3-fpm", "8.3.6-0ubuntu0.24.04.11"),),
        )

    def test_unfinished_package_is_unsupported_not_absent(self) -> None:
        # "iU" is unpacked but not configured: the software may be partly present.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            0, DPKG_OUTPUT.replace("nginx 1.24.0-2ubuntu7.18 ii", "nginx 1.24.0-2ubuntu7.18 iU")
        )
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(
            (nginx.package.outcome, nginx.service.outcome), ("unsupported", "unsupported")
        )
        self.assertEqual(nginx.package.value, ())
        self.assertFalse([c for c in self.remote.commands if "nginx.service" in c])
        self.assert_not_kept("1.24.0-2ubuntu7.18")
        self.assertIn("lists a Nginx package that is not fully installed", nginx.package.warning)

    def test_every_installed_php_fpm_package_gets_its_unit_queried(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            0,
            "php8.1-fpm 8.1.2-1ubuntu2 ii \nphp8.3-fpm 8.3.6-0ubuntu0.24.04.11 ii \n"
            + DPKG_OUTPUT.splitlines()[2]
            + "\n",
        )
        self.remote.results[UNIT_QUERY.format("php8.1-fpm.service php8.3-fpm.service")] = (
            ssh.CommandResult(
                0,
                # systemctl separates the records of several units with an empty line.
                unit_report("php8.1-fpm.service") + "\n" + unit_report("php8.3-fpm.service"),
            )
        )
        self.collect()
        self.assertEqual(
            self.component("php-fpm").service.value,
            (
                ServiceUnit("php8.1-fpm.service", "loaded", "active", "running", "enabled"),
                ServiceUnit("php8.3-fpm.service", "loaded", "active", "running", "enabled"),
            ),
        )


class PostgresClusterTests(ObservationTestCase):
    """docs/ssh-connections.md#postgresql-clusters"""

    def postgres(self) -> WebStackComponentObservation:
        return self.component("postgresql")

    def postgres_commands(self) -> list[str]:
        """The commands issued after the package query to observe PostgreSQL's service."""
        return [c for c in self.remote.commands if "postgres" in c and c != PACKAGE_QUERY]

    def test_running_cluster_is_reported_with_the_command_that_found_it(self) -> None:
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertEqual(
            postgres.service.value,
            (UMBRELLA_UNIT, MAIN_UNIT),
        )
        self.assertEqual(
            self.postgres_commands(),
            [
                f"ls -1b {PG_DIR}",
                f"ls -1bA {PG_DIR}/16",
                f"test -e {cluster_conf('16', 'main')}",
                UNIT_QUERY.format(CLUSTER_UNITS),
            ],
        )
        self.assertEqual(
            list(postgres.service.source),
            [f"ls -1b {PG_DIR}", f"ls -1bA {PG_DIR}/16", UNIT_QUERY.format(CLUSTER_UNITS)],
        )
        self.assertEqual(postgres.service.warning, "")

    def add_cluster(self, version: str, name: str) -> None:
        versions = self.remote.directories[PG_DIR]
        if version not in versions:
            versions.append(version)
        self.remote.directories.setdefault(f"{PG_DIR}/{version}", []).append(name)
        self.remote.directories[f"{PG_DIR}/{version}/{name}"] = ["postgresql.conf"]
        self.remote.files[cluster_conf(version, name)] = ""

    def report_units(self, units: str, *reports: str) -> None:
        self.remote.results[UNIT_QUERY.format(units)] = ssh.CommandResult(0, "\n".join(reports))

    def test_stopped_cluster_is_installed_but_stopped_under_a_running_umbrella(self) -> None:
        self.report_units(
            CLUSTER_UNITS,
            UMBRELLA_REPORT,
            cluster_report("16", "main", active="inactive", sub="dead"),
        )
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertEqual(
            postgres.service.value,
            (
                UMBRELLA_UNIT,
                ServiceUnit(
                    "postgresql@16-main.service", "loaded", "inactive", "dead", "enabled-runtime"
                ),
            ),
        )

    def test_no_clusters_is_observed_with_only_the_umbrella_unit(self) -> None:
        # pg_dropcluster removes a cluster's directory and may leave its version directory.
        self.remote.directories[f"{PG_DIR}/16"] = []
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertEqual(postgres.service.value, (UMBRELLA_UNIT,))
        self.assertEqual(
            postgres.service.warning, f"Barectl found no PostgreSQL clusters in {PG_DIR}."
        )
        # The note is a finding, not a warning.
        self.assertEqual(self.warned(), [])

    def assert_uninspected(self, status: str, warning: str) -> WebStackComponentObservation:
        """Assert the clusters could not all be seen: never absent, versions still kept."""
        postgres = self.postgres()
        self.assertEqual(postgres.package.outcome, "observed")
        self.assertIn(Package("postgresql-16", "16.15-0ubuntu0.24.04.1"), postgres.package.value)
        self.assertEqual(postgres.service.outcome, status)
        self.assertEqual(postgres.service.warning, warning)
        self.assert_nothing_absent()
        return postgres

    def test_unreadable_configuration_root_is_inaccessible_not_absent(self) -> None:
        del self.remote.directories[PG_DIR]
        self.remote.unreadable.add(PG_DIR)
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        postgres = self.assert_uninspected(
            "inaccessible",
            f"The SSH user cannot read {PG_DIR}. Barectl does not use sudo.",
        )
        self.assertEqual(postgres.service.value, (UMBRELLA_UNIT,))
        self.assertEqual(
            list(postgres.service.source),
            [f"ls -1b {PG_DIR}", UNIT_QUERY.format("postgresql.service")],
        )

    def test_unreadable_version_directory_is_inaccessible_and_keeps_other_clusters(self) -> None:
        self.add_cluster("17", "main")
        del self.remote.directories[f"{PG_DIR}/16"]
        self.remote.unreadable.add(f"{PG_DIR}/16")
        units = "postgresql.service postgresql@17-main.service"
        self.report_units(units, UMBRELLA_REPORT, cluster_report("17", "main"))
        self.collect()
        postgres = self.assert_uninspected(
            "inaccessible", f"The SSH user cannot read {PG_DIR}/16. Barectl does not use sudo."
        )
        self.assertEqual(
            postgres.service.value,
            (
                UMBRELLA_UNIT,
                ServiceUnit(
                    "postgresql@17-main.service", "loaded", "active", "running", "enabled-runtime"
                ),
            ),
        )

    def test_unavailable_systemd_keeps_the_listing_warning(self) -> None:
        del self.remote.directories[PG_DIR]
        self.remote.unreadable.add(PG_DIR)
        self.remote.results[UNIT_QUERY.format("postgresql.service")] = ssh.CommandResult(1, "")
        self.collect()
        postgres = self.postgres()
        self.assertEqual((postgres.service.outcome, postgres.service.value), ("unsupported", ()))
        self.assertIn("could not read service states from systemd.", postgres.service.warning)
        self.assertIn(f"The SSH user cannot read {PG_DIR}.", postgres.service.warning)

    def test_missing_configuration_root_is_unsupported_not_absent(self) -> None:
        # postgresql-common installs /etc/postgresql; without it the layout is not Debian's.
        for described in (self.remote.directories, self.remote.files):
            for path in [path for path in described if path.startswith(PG_DIR)]:
                del described[path]
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        self.assert_uninspected(
            "unsupported", f"The server has no {PG_DIR}. Barectl reads only the Debian layout."
        )

    def test_listing_that_cannot_run_is_unsupported(self) -> None:
        self.remote.results[f"ls -1b {PG_DIR}"] = ssh.CommandResult(127, "")
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        self.assert_uninspected("unsupported", f"{PG_DIR} could not be read.")

    def test_truncated_listing_is_unsupported(self) -> None:
        self.remote.results[f"ls -1bA {PG_DIR}/16"] = ssh.CommandResult(0, "main\n", truncated=True)
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        self.assert_uninspected(
            "unsupported", f"{PG_DIR}/16 holds more than 1000 entries. It was not read."
        )

    def test_more_clusters_than_supported_are_not_queried(self) -> None:
        self.remote.directories[f"{PG_DIR}/16"] = [f"c{n:03}" for n in range(101)]
        for n in range(101):
            self.remote.files[cluster_conf("16", f"c{n:03}")] = ""
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        self.assert_uninspected(
            "unsupported",
            f"{PG_DIR} holds more than 100 possible PostgreSQL clusters. They were not queried.",
        )
        self.assertFalse([c for c in self.remote.commands if "c000" in c])
        self.assertEqual(self.postgres().service.value, (UMBRELLA_UNIT,))

    def test_more_versions_than_supported_are_not_listed(self) -> None:
        self.remote.directories[PG_DIR] = [str(version) for version in range(10, 31)]
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        self.assert_uninspected(
            "unsupported",
            f"{PG_DIR} holds more than 20 PostgreSQL versions. They were not listed.",
        )
        self.assertEqual(self.postgres_commands()[1:], [UNIT_QUERY.format("postgresql.service")])

    def test_cluster_without_a_unit_file_is_reported_as_not_found(self) -> None:
        self.report_units(
            CLUSTER_UNITS,
            UMBRELLA_REPORT,
            "Id=postgresql@16-main.service\nLoadState=not-found\nActiveState=inactive\n"
            "SubState=dead\nUnitFileState=\n",
        )
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertIn(
            ServiceUnit("postgresql@16-main.service", "not-found", "inactive", "dead", ""),
            postgres.service.value,
        )

    def test_cluster_reported_under_another_name_is_unsupported(self) -> None:
        self.report_units(CLUSTER_UNITS, UMBRELLA_REPORT, unit_report("postgresql@17-main.service"))
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "unsupported")
        self.assertEqual(postgres.service.value, (UMBRELLA_UNIT,))
        self.assert_not_kept("postgresql@17-main")

    def test_hostile_names_are_never_used_in_commands_or_warnings(self) -> None:
        # As ls -b prints them: spaces and newlines escaped with backslashes.
        hostile = ["db;reboot", "my\\ db", "x\\ny", "$(id)"]
        self.remote.directories[PG_DIR] += ["16;reboot", "17\\nmain"]
        self.remote.directories[f"{PG_DIR}/16"] += hostile
        self.collect()
        postgres = self.assert_uninspected(
            "unsupported",
            f"{PG_DIR}/16 lists 4 entries whose names Barectl does not support. They were skipped.",
        )
        self.assertIn(MAIN_UNIT, postgres.service.value)
        self.assertEqual(
            self.postgres_commands(),
            [
                f"ls -1b {PG_DIR}",
                f"ls -1bA {PG_DIR}/16",
                f"test -e {cluster_conf('16', 'main')}",
                UNIT_QUERY.format(CLUSTER_UNITS),
            ],
        )
        stored = " ".join(
            (
                *(state for unit in postgres.service.value for state in unit),
                postgres.service.warning,
                *postgres.service.source,
            )
        )
        for name in [*hostile, "16;reboot", "17\\nmain", "reboot", "(id)"]:
            with self.subTest(name=name):
                self.assertNotIn(name, stored)
                self.assert_not_kept(name)

    def test_dead_configuration_symlink_still_marks_a_cluster(self) -> None:
        # postgresql-common counts a postgresql.conf that is a dead symlink.
        del self.remote.files[cluster_conf("16", "main")]
        self.remote.dead_links.add(cluster_conf("16", "main"))
        self.collect()
        self.assertEqual(self.postgres().service.outcome, "observed")
        self.assertIn(MAIN_UNIT, self.postgres().service.value)
        self.assertIn(f"test -L {cluster_conf('16', 'main')}", self.postgres_commands())

    def test_cluster_named_with_a_leading_dot_is_found(self) -> None:
        # postgresql-common reads every directory entry, including names starting with ".".
        self.add_cluster("16", ".staging")
        units = f"{CLUSTER_UNITS} postgresql@16-.staging.service"
        self.report_units(
            units, UMBRELLA_REPORT, cluster_report("16", "main"), cluster_report("16", ".staging")
        )
        self.collect()
        self.assertEqual(
            self.postgres().service.value,
            (
                UMBRELLA_UNIT,
                MAIN_UNIT,
                ServiceUnit(
                    "postgresql@16-.staging.service",
                    "loaded",
                    "active",
                    "running",
                    "enabled-runtime",
                ),
            ),
        )

    def test_entries_without_postgresql_conf_are_not_clusters(self) -> None:
        # A searchable directory without postgresql.conf, and a plain file.
        self.remote.directories[f"{PG_DIR}/16"] += ["old", "README"]
        self.remote.directories[f"{PG_DIR}/16/old"] = []
        self.remote.files[f"{PG_DIR}/16/README"] = "notes"
        self.collect()
        postgres = self.postgres()
        self.assertEqual((postgres.service.outcome, postgres.service.warning), ("observed", ""))
        self.assertEqual(
            postgres.service.value,
            (UMBRELLA_UNIT, MAIN_UNIT),
        )

    def test_unsearchable_cluster_directory_is_inaccessible(self) -> None:
        self.add_cluster("16", "private")
        self.remote.unsearchable.add(f"{PG_DIR}/16/private")
        self.collect()
        postgres = self.assert_uninspected(
            "inaccessible",
            f"The SSH user cannot search {PG_DIR}/16/private. Barectl does not use sudo.",
        )
        self.assertIn(MAIN_UNIT, postgres.service.value)
        self.assertNotIn(
            "postgresql@16-private.service", [unit.name for unit in postgres.service.value]
        )

    def test_clusters_are_not_looked_for_without_an_installed_package(self) -> None:
        # Not installed, and unpacked but not configured.
        for dpkg, status in (("", "absent"), ("postgresql 16+257build1.1 iU \n", "unsupported")):
            with self.subTest(status=status):
                self.remote.commands.clear()
                self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, dpkg)
                self.collect()
                self.assertEqual(self.postgres_commands(), [])
                self.assertEqual(self.postgres().service.outcome, status)

    def test_every_cluster_of_every_version_is_queried_whether_loaded_or_not(self) -> None:
        # A manual cluster is not wanted by the umbrella unit, so systemd has not loaded it;
        # querying it by name loads it, and it reports "disabled".
        self.add_cluster("16", "reports")
        self.add_cluster("9.6", "legacy")
        units = (
            "postgresql.service postgresql@9.6-legacy.service postgresql@16-main.service "
            "postgresql@16-reports.service"
        )
        self.report_units(
            units,
            UMBRELLA_REPORT,
            cluster_report("9.6", "legacy", active="failed", sub="failed"),
            cluster_report("16", "main"),
            cluster_report("16", "reports", active="inactive", sub="dead", file_state="disabled"),
        )
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertEqual(
            postgres.service.value,
            (
                UMBRELLA_UNIT,
                ServiceUnit(
                    "postgresql@9.6-legacy.service", "loaded", "failed", "failed", "enabled-runtime"
                ),
                MAIN_UNIT,
                ServiceUnit(
                    "postgresql@16-reports.service", "loaded", "inactive", "dead", "disabled"
                ),
            ),
        )
        self.assertEqual(
            self.postgres_commands(),
            [
                f"ls -1b {PG_DIR}",
                f"ls -1bA {PG_DIR}/9.6",
                f"ls -1bA {PG_DIR}/16",
                f"test -e {cluster_conf('9.6', 'legacy')}",
                f"test -e {cluster_conf('16', 'main')}",
                f"test -e {cluster_conf('16', 'reports')}",
                UNIT_QUERY.format(units),
            ],
        )
