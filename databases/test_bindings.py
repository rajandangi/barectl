"""Binding plans (docs/databases.md#database-bindings): request, worker, review, apply.

Real views, services, the lifecycle, the worker, persistence and rendering run; only remote
execution is substituted. These tests establish what Barectl reviews and submits; the
tests tagged ssh establish what the engines do.
"""

import re
import shlex
from typing import ClassVar, override
from unittest import mock

from bootstrap import apply as bootstrap_apply
from bootstrap.fakes import RESOLUTE_PACKAGING, NativeSystemd, Packaging
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from bootstrap.profiles import PROFILES
from discovery.models import DatabaseEngine
from discovery.observations.databases import (
    MARIADB_STEPS,
    POSTGRESQL_STEPS,
    Step,
    satisfied_mariadb_rows,
    satisfied_postgresql_rows,
    satisfied_postgresql_schema,
)
from operations.models import RemoteOperation
from servers.testing import HTMX_FRAGMENT

from . import binding, native
from .fakes import DATABASE_APPLY, DATABASE_PERMISSIONS, DatabaseTestCase
from .models import (
    DatabaseRequest,
    DatabaseRunResult,
    PlanDatabaseBinding,
    RunDatabaseBinding,
)

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
Kind = PlanEvidence.Kind
Status = RemoteOperation.Status
NAME_PART = "0123456789abcdef0123456789abcdef"


class BindingTestCase(DatabaseTestCase):
    action = "database_mariadb"

    def binding_plan(self, identifier: str = "shop") -> ConfigurationPlan:
        self.prepare_database(identifier, self.action)
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if plan is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return plan

    def texts(self, plan: ConfigurationPlan) -> str:
        return " ".join(plan.refusals.values_list("text", flat=True))


class BindingReviewTests(BindingTestCase):
    def test_a_complete_site_with_the_engine_and_driver_admits_the_binding(self) -> None:
        plan = self.binding_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        record = PlanDatabaseBinding.objects.get(plan=plan)
        self.assertEqual(
            (record.principal, record.uid, record.gid, record.character_set, record.collation),
            ("sshop", 1003, 1003, "utf8mb4", "utf8mb4_unicode_ci"),
        )
        self.assertEqual(record.probe_path, f"/var/www/shop/dbprobe-{record.probe_token}.php")
        self.assertEqual(
            record.probe_content,
            binding.render_probe(DatabaseEngine.MARIADB, "sshop", record.probe_token),
        )
        statements = list(plan.binding_statements.values_list("step", "text"))
        self.assertEqual(
            statements,
            [
                ("principal", "CREATE USER `sshop`@`localhost` IDENTIFIED VIA unix_socket"),
                (
                    "database",
                    "CREATE DATABASE `sshop` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
                ),
                (
                    "privileges",
                    (
                        "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, "
                        "REFERENCES, CREATE TEMPORARY TABLES, LOCK TABLES ON `sshop`.* TO "
                        "`sshop`@`localhost`"
                    ),
                ),
            ],
        )
        kinds = set(plan.effects.values_list("kind", flat=True))
        self.assertLessEqual(
            {
                Effect.DATABASE_PRINCIPAL,
                Effect.DATABASE_CREATION,
                Effect.DATABASE_PRIVILEGES,
                Effect.ACCEPTANCE_PROBE,
                Effect.CONNECTION,
                Effect.NO_ROLLBACK,
            },
            kinds,
        )
        connection = plan.effects.get(kind=Effect.CONNECTION).text
        self.assertIn("mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=sshop", connection)
        evidence = set(plan.evidence.values_list("kind", flat=True))
        self.assertLessEqual(
            {
                Kind.SITE_REVALIDATION,
                Kind.PACKAGE_REVALIDATION,
                Kind.DRIVER,
                Kind.CATALOG,
                Kind.CATALOG_REVALIDATION,
                Kind.CATALOG_AFTER,
            },
            evidence,
        )
        self.assertLess(record.payload_bytes or 0, 16 * 1024 - 2048)

    def test_the_predicted_catalog_is_the_convention_s_rows(self) -> None:
        before = f"{binding.MARIADB_SECTION}\nP\tACTIVE\n"
        after = binding.predicted_after(before, DatabaseEngine.MARIADB, "sshop")
        self.assertEqual(after, f"{before}{satisfied_mariadb_rows('sshop')}")
        with_other = f"{before}{binding.POSTGRESQL_SECTION}\n"
        self.assertEqual(
            binding.predicted_after(with_other, DatabaseEngine.MARIADB, "sshop"),
            f"{before}{satisfied_mariadb_rows('sshop')}{binding.POSTGRESQL_SECTION}\n",
        )

    def test_a_satisfied_binding_is_a_no_op(self) -> None:
        self.database.satisfy("sshop")
        plan = self.binding_plan()
        self.assertTrue(plan.eligible and plan.no_changes, self.texts(plan))

    def test_a_partial_binding_names_the_remaining_statements(self) -> None:
        self.database.mariadb = satisfied_mariadb_rows("sshop", MARIADB_STEPS[:1])
        plan = self.binding_plan()
        self.assertEqual(self.reasons(plan), [Reason.PARTIAL_BINDING])
        self.assertIn("CREATE DATABASE `sshop`", self.texts(plan))
        self.assertIn("Barectl never resumes or adopts a partial binding", self.texts(plan))

    def test_custom_rows_are_a_collision(self) -> None:
        self.database.mariadb = satisfied_mariadb_rows("sshop") + "T\tsshop\ttables_priv\t1\n"
        plan = self.binding_plan()
        self.assertEqual(self.reasons(plan), [Reason.COLLISION])
        self.assertIn("does not create", self.texts(plan))

    def test_other_accounts_grants_that_reach_the_name_are_a_collision(self) -> None:
        for rows in ("G\tsshop\tx\t%\ts%\n", "F\tsshop\tproxies_priv\t1\n"):
            with self.subTest(rows=rows):
                self.database.mariadb = rows
                plan = self.binding_plan()
                self.assertEqual(self.reasons(plan), [Reason.COLLISION])
                self.assertIn("Other accounts' grants reach sshop", self.texts(plan))

    def test_the_other_engine_holding_the_name_is_an_existing_binding(self) -> None:
        self.site.ubuntu.postgresql = "installed"
        self.database.other = "A|sshop\n"
        plan = self.binding_plan()
        self.assertEqual(self.reasons(plan), [Reason.EXISTING_BINDING])
        read = self.database.catalog_reads[-1]
        self.assertIn(binding.POSTGRESQL_SECTION, read)

    def prerequisite(self) -> None:
        plan = self.binding_plan()
        self.assertIn(Reason.PREREQUISITE, self.reasons(plan), self.texts(plan))
        self.assertFalse(PlanDatabaseBinding.objects.filter(plan=plan).exists())

    def test_the_site_is_a_prerequisite(self) -> None:
        self.site.sites.clear()
        self.prerequisite()

    def test_the_established_engine_is_a_prerequisite(self) -> None:
        self.site.ubuntu.mariadb_active = "inactive"
        self.prerequisite()

    def test_the_driver_is_a_prerequisite(self) -> None:
        self.site.drivers = ()
        self.prerequisite()

    def test_the_catalog_read_is_never_a_change(self) -> None:
        self.binding_plan()
        (read,) = self.database.catalog_reads
        for word in ("CREATE", "GRANT", "DROP", "INSERT"):
            self.assertIsNone(re.search(rf"\\b{word}\\b", read))
        self.assertIn(binding.MARIADB_SECTION, read)

    def test_an_existing_probe_path_is_a_collision(self) -> None:
        self.database.probe_exists = True
        plan = self.binding_plan()
        self.assertIn(Reason.COLLISION, self.reasons(plan))

    def test_reading_needs_privilege(self) -> None:
        self.site.privilege = "narrow"
        plan = self.binding_plan()
        self.assertIn(Reason.PRIVILEGE, self.reasons(plan))

    def test_the_review_is_rendered(self) -> None:
        plan = self.binding_plan()
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "Statements, each in its own client invocation")
        self.assertContains(page, "CREATE USER `sshop`@`localhost` IDENTIFIED VIA unix_socket")
        self.assertContains(page, "mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=sshop")


class ResoluteBindingReviewTests(BindingReviewTests):
    packaging: ClassVar[Packaging] = RESOLUTE_PACKAGING


class BindingRequestTests(BindingTestCase):
    def test_an_invalid_identifier_is_refused_before_anything_is_queued(self) -> None:
        self.sign_in_with(*DATABASE_PERMISSIONS)
        response = self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": "database_mariadb", "identifier": "Shop!"},
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 422)
        self.assertContains(response, "lowercase letters and digits", status_code=422)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_the_request_is_kept_with_the_preparation(self) -> None:
        self.binding_plan()
        request = DatabaseRequest.objects.get()
        self.assertEqual((request.identifier, request.engine), ("shop", "mariadb"))

    def test_site_and_bootstrap_permissions_grant_nothing(self) -> None:
        response = self.prepare_database(
            perms=("view_server", "view_siteplan", "prepare_siteplan", "prepare_configurationplan")
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(PlanPreparation.objects.exists())


APPLY_READS = re.compile(
    r"\A(sudo -n (-l )?)?/usr/bin/systemd-run --unit=barectl-apply-[0-9a-f]{32}"
    r"|\A(id -u|cat /proc/sys/kernel/random/boot_id; systemctl show .*)\Z"
    r"|\Asystemctl list-units .*|\Asha256sum /var/lib/dpkg/status.*"
    r"|\Aapt-mark (showauto|showmanual).*"
    r"|\A(sudo -n (-l )?)?/usr/bin/sh -c '.*'\Z",
    re.DOTALL,
)


class BindingApplyTests(BindingTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.systemd.answer(self.remote)
        self.systemd.on_submit = self.created
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    @override
    def assert_read_only(self) -> None:
        self.remote.commands[:] = [c for c in self.remote.commands if not APPLY_READS.match(c)]
        super().assert_read_only()

    def created(self) -> None:
        if self.systemd.exit_status == 0 and not self.database.mariadb:
            self.database.satisfy("sshop")
        profile = PROFILES[self.packaging.release.version][Action.MARIADB]
        self.database.state = (
            f"{binding.MARIADB_SECTION}\nP\tACTIVE\n{self.database.mariadb}"
            f"== readiness\n{profile.check.expected}\n== state\nprobe absent\n"
            "unit mariadb.service active/running\n"
            f"unit php{self.packaging.release.php}-fpm.service active/running\nlistening 1\n"
        )

    def apply(self) -> ApplyRun:
        plan = self.binding_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        self.sign_in_with(*DATABASE_APPLY)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.run_worker()
        return ApplyRun.objects.get(plan_number=plan.pk)

    def payload(self) -> str:
        (submission,) = self.systemd.submissions
        return shlex.split(submission)[-1]

    def test_the_statements_run_in_order_between_the_checks(self) -> None:
        run = self.apply()
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            (run.failure, run.notes if hasattr(run, "notes") else ""),
        )
        payload = self.payload()
        record = RunDatabaseBinding.objects.get(run=run)
        positions = [
            payload.index(fragment)
            for fragment in (
                f"w /var/www/shop dbprobe-{record.probe_token}.php root:sshop 0640",
                "pre)\" = 'barectl-db",
                "CREATE USER `sshop`",
                "CREATE DATABASE `sshop`",
                "GRANT SELECT",
                "full)\" = 'barectl-db",
                "barectl-database: verified",
            )
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("IF NOT EXISTS", payload)
        self.assertNotIn("DROP ", payload.replace("DROP TABLE", "").replace("DROP, ", ""))
        result = DatabaseRunResult.objects.get(run=run)
        self.assertEqual((result.principal, result.probe_absent), ("sshop@localhost", True))
        self.assertIn("Run CREATE USER `sshop`@`localhost`", run.reviewed_changes)

    def test_each_boundary_is_named(self) -> None:
        cases = {
            native.Exit.DRIVER_UNAVAILABLE: (Execution.DRIVER_UNAVAILABLE, "driver loaded"),
            native.Exit.PRINCIPAL_CONFLICT: (Execution.PRINCIPAL_CONFLICT, "already existed"),
            native.Exit.PRINCIPAL_REFUSED: (Execution.STATEMENT_REFUSED, "catalog is unchanged"),
            native.Exit.DATABASE_EXISTS: (Execution.PARTIAL, "already existed and was not adopted"),
            native.Exit.PRIVILEGES_FAILED: (Execution.PARTIAL, "granting the convention"),
            native.Exit.AFTER_STATE: (Execution.PARTIAL, "differs from the reviewed result"),
            native.Exit.PROOF_FAILED: (Execution.PARTIAL, "could not use it as reviewed"),
            native.Exit.PROBE_LEFT: (Execution.PARTIAL, "could not be removed"),
            native.Exit.PROBE_FAILED: (Execution.PARTIAL, "catalog is unchanged"),
        }
        for code, (execution, text) in cases.items():
            with self.subTest(code=code):
                ApplyRun.objects.all().delete()
                PlanPreparation.objects.all().delete()
                self.systemd.submissions.clear()
                self.database.mariadb = ""
                self.systemd.exit_status = code
                self.systemd.result = "exit-code"
                run = self.apply()
                self.assertEqual((run.execution, run.exit_status), (execution, code))
                self.assertIn(text, run.failure)

    def test_a_binding_that_differs_after_the_run_fails_verification(self) -> None:
        def created_with_a_grant() -> None:
            self.database.mariadb = satisfied_mariadb_rows("sshop")
            self.database.mariadb += "T\tsshop\ttables_priv\t1\n"
            self.created()

        self.systemd.on_submit = created_with_a_grant
        run = self.apply()
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn("does not follow the database convention", run.failure)


class PayloadTests(BindingTestCase):
    def change(self, **overrides: object) -> native.BindingChange:
        values: dict[str, object] = {
            "release": self.packaging.release.version,
            "identifier": "shop",
            "engine": DatabaseEngine.MARIADB,
            "uid": 1003,
            "gid": 1003,
            "token": NAME_PART,
            "probe": binding.render_probe(DatabaseEngine.MARIADB, "sshop", NAME_PART),
            "site_digest": "a" * 64,
            "engine_digest": "b" * 64,
            "driver_version": "8.3.6-0ubuntu0.24.04.11",
            "catalog_before": "c" * 64,
            "catalog_after": "d" * 64,
            "other": True,
            "locale": "",
            "statements": binding.statements(DatabaseEngine.MARIADB, "sshop"),
        }
        values.update(overrides)
        return native.BindingChange(**values)  # type: ignore[arg-type]

    def test_tampered_values_are_refused(self) -> None:
        tampered = {
            "statements": (
                binding.Statement(Step.PRINCIPAL, "", "CREATE USER x"),
                *binding.statements(DatabaseEngine.MARIADB, "sshop")[1:],
            ),
            "probe": "<?php echo 1;\n",
            "site_digest": "not a digest",
            "uid": 0,
            "driver_version": "1.0; rm -rf /",
        }
        for field, value in tampered.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                native.binding_payload(
                    "barectl-apply-" + "e" * 32 + ".service",
                    "0" * 8 + "-0000-0000-0000-" + "0" * 12,
                    1,
                    self.change(**{field: value}),
                )

    def postgresql(self, name: str = "sshop", locale: str = "C.UTF-8") -> dict[str, object]:
        engine = DatabaseEngine.POSTGRESQL
        return {
            "engine": engine,
            "probe": binding.render_probe(engine, name, NAME_PART),
            "locale": locale,
            "statements": binding.statements(engine, name, locale),
        }

    def test_a_locale_off_the_allowlist_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            binding.statements(DatabaseEngine.POSTGRESQL, "sshop", "de_DE.UTF-8")
        with self.assertRaises(ValueError):
            native.binding_payload(
                "barectl-apply-" + "e" * 32 + ".service",
                "0" * 8 + "-0000-0000-0000-" + "0" * 12,
                1,
                self.change(**{**self.postgresql(), "locale": "en_US.UTF-8"}),
            )

    def test_the_largest_payload_keeps_a_margin(self) -> None:
        name = "a" * 24
        for engine in (DatabaseEngine.MARIADB, DatabaseEngine.POSTGRESQL):
            with self.subTest(engine=engine):
                values = (
                    self.postgresql(f"s{name}")
                    if engine == DatabaseEngine.POSTGRESQL
                    else {
                        "probe": binding.render_probe(engine, f"s{name}", NAME_PART),
                        "statements": binding.statements(engine, f"s{name}"),
                    }
                )
                change = self.change(identifier=name, uid=60000, gid=60000, **values)
                text = native.binding_payload(
                    "barectl-apply-" + "e" * 32 + ".service",
                    "00000000-0000-0000-0000-000000000000",
                    99_999_999,
                    change,
                )
                self.assertLess(len(text.encode()), 16 * 1024 - 2048)

    def test_identifiers_are_always_quoted(self) -> None:
        for statement in binding.statements(DatabaseEngine.MARIADB, "sselect"):
            self.assertIn("`sselect`", statement.text)
        for statement in binding.statements(DatabaseEngine.POSTGRESQL, "sselect", "C.UTF-8")[:3]:
            self.assertIn('"sselect"', statement.text)


class PostgreSQLBindingTests(BindingTestCase):
    """The same plans for PostgreSQL: its own statements, template1's locale and schema."""

    action = "database_postgresql"

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.drivers = ("pgsql",)
        self.database.engine = DatabaseEngine.POSTGRESQL
        self.systemd = NativeSystemd()
        self.systemd.answer(self.remote)
        self.systemd.on_submit = self.created
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    @override
    def assert_read_only(self) -> None:
        self.remote.commands[:] = [c for c in self.remote.commands if not APPLY_READS.match(c)]
        super().assert_read_only()

    def created(self) -> None:
        if self.systemd.exit_status == 0 and not self.database.postgresql:
            self.database.satisfy("sshop")
        profile = PROFILES[self.packaging.release.version][Action.POSTGRESQL]
        units = "".join(f"unit {unit} active/running\n" for unit in (profile.serving_unit,))
        self.database.state = (
            f"{self.database.catalog(other=False)}== readiness\n{profile.check.expected}\n"
            f"== state\nprobe absent\n{units}"
            f"unit php{self.packaging.release.php}-fpm.service active/running\nlistening 1\n"
        )

    def test_a_fresh_binding_prepares_without_the_other_engine_installed(self) -> None:
        self.assertEqual(self.site.ubuntu.mariadb, "absent")
        plan = self.binding_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        self.assertFalse(PlanDatabaseBinding.objects.get(plan=plan).other_engine)

    def test_the_convention_s_statements_are_reviewed_with_template1_s_locale(self) -> None:
        plan = self.binding_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        record = PlanDatabaseBinding.objects.get(plan=plan)
        self.assertEqual((record.character_set, record.collation), ("UTF8", "C.UTF-8"))
        self.assertEqual(
            list(plan.binding_statements.values_list("step", "database", "text")),
            [
                (
                    "principal",
                    "postgres",
                    (
                        'CREATE ROLE "sshop" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT '
                        "NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD NULL"
                    ),
                ),
                (
                    "database",
                    "postgres",
                    (
                        'CREATE DATABASE "sshop" WITH OWNER "sshop" TEMPLATE template0 '
                        "ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE 'C.UTF-8' "
                        "LC_CTYPE 'C.UTF-8'"
                    ),
                ),
                (
                    "privileges",
                    "postgres",
                    'REVOKE CONNECT, TEMPORARY ON DATABASE "sshop" FROM PUBLIC',
                ),
                ("schema", "sshop", "REVOKE ALL ON SCHEMA public FROM PUBLIC"),
            ],
        )
        self.assertIn(
            "pgsql:host=/var/run/postgresql", " ".join(plan.effects.values_list("text", flat=True))
        )

    def test_another_template_locale_is_refused(self) -> None:
        for template in ("T|UTF8|c|de_DE.UTF-8|de_DE.UTF-8\n", "T|UTF8|i|und|und\n"):
            with self.subTest(template=template):
                self.database.template = template
                plan = self.binding_plan()
                self.assertEqual(self.reasons(plan), [Reason.CUSTOMIZED])
                self.assertIn("template1 uses UTF8", self.texts(plan))

    def test_a_satisfied_binding_has_no_changes_and_a_partial_one_is_refused(self) -> None:
        self.database.satisfy("sshop")
        self.assertTrue(self.binding_plan().no_changes)
        self.database.postgresql = satisfied_postgresql_rows("sshop", POSTGRESQL_STEPS[:2])
        self.database.schema = satisfied_postgresql_schema(POSTGRESQL_STEPS[:2])
        plan = self.binding_plan()
        self.assertEqual(self.reasons(plan), [Reason.PARTIAL_BINDING])
        self.assertIn("REVOKE ALL ON SCHEMA public FROM PUBLIC", self.texts(plan))

    def test_the_statements_run_in_their_databases_and_the_binding_is_verified(self) -> None:
        plan = self.binding_plan()
        self.sign_in_with(*DATABASE_APPLY)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.run_worker()
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.assertEqual(
            (run.status, run.verification), (Status.SUCCEEDED, Verification.PASSED), run.failure
        )
        (submission,) = self.systemd.submissions
        payload = shlex.split(submission)[-1]
        positions = [
            payload.index(fragment)
            for fragment in (
                'q postgres \'CREATE ROLE "sshop"',
                'q postgres \'CREATE DATABASE "sshop"',
                "q postgres 'REVOKE CONNECT, TEMPORARY",
                "q sshop 'REVOKE ALL ON SCHEMA public FROM PUBLIC'",
            )
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("ERROR:  42710", payload)
        self.assertEqual(DatabaseRunResult.objects.get(run=run).principal, "sshop")

    def test_a_failed_schema_revoke_is_partial(self) -> None:
        self.systemd.exit_status = native.Exit.SCHEMA_FAILED
        self.systemd.result = "exit-code"
        plan = self.binding_plan()
        self.sign_in_with(*DATABASE_APPLY)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.run_worker()
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.assertEqual((run.execution, run.exit_status), (Execution.PARTIAL, 60))
        self.assertIn("revoking PUBLIC's rights on the public schema failed", run.failure)
