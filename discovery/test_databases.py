"""Site database bindings (docs/ssh-connections.md#site-database-observations).

The catalog rows follow the engines' own output, recorded in
docs/v0.3-qualification.md#site-database-observations.
"""

from dataclasses import replace
from typing import override

from django.test import SimpleTestCase

from . import ssh
from .fakes import (
    DPKG_OUTPUT,
    HBA_FILE,
    PACKAGE_QUERY,
    POSTGRESQL_HBA,
    POSTGRESQL_SERVER,
    UNIT_QUERY,
    ObservationTestCase,
    add_site,
    mariadb_rows,
    postgresql_rows,
    schema_row,
    unit_report,
)
from .models import DatabaseEngine, ObservationOutcome
from .observations.databases import (
    MARIADB_CLIENT,
    MARIADB_PRIVILEGES,
    MARIADB_STEPS,
    POSTGRESQL_CLIENT,
    POSTGRESQL_STEPS,
    ROOT_QUERY,
    Binding,
    BindingState,
    Step,
    collect_databases,
    mariadb_catalog_sql,
    parse_mariadb,
    parse_postgresql,
    parse_postgresql_schema,
    postgresql_catalog_sql,
    recognize_mariadb,
    recognize_postgresql,
    with_schema,
)
from .presentation import DATABASE_NOT_COLLECTED, present_sites
from .snapshot import ObservedDatabase

CLIENTS = (MARIADB_CLIENT, POSTGRESQL_CLIENT)
SHOP = "sshop"
BLOG = "sblog"
KEYS = '["access", "version_id", "plugin", "authentication_string", "password_last_changed"]'


def mariadb(rows: str, name: str = SHOP, plugin: str = "ACTIVE") -> BindingState:
    return mariadb_binding(rows, name, plugin).state


def mariadb_binding(rows: str, name: str = SHOP, plugin: str = "ACTIVE") -> Binding:
    return recognize_mariadb(parse_mariadb(f"P\t{plugin}\n{rows}", (name,)), name)


def postgresql_binding(
    rows: str,
    schema: str | None = None,
    hba: str = POSTGRESQL_HBA,
    name: str = BLOG,
    server: str = POSTGRESQL_SERVER,
) -> Binding:
    catalog = parse_postgresql(f"{server}{rows}{hba}", (name,))
    if schema is not None:
        with_schema(catalog, name, parse_postgresql_schema(schema))
    return recognize_postgresql(catalog, name)


def hba_rule(number: int | None, line: int, rest: str, file: str = HBA_FILE) -> str:
    return f"H|{'' if number is None else number}|{file}|{line}|{rest}\n"


class MariaDBRecognitionTests(SimpleTestCase):
    def test_nothing_under_the_name_is_absent(self) -> None:
        self.assertEqual(mariadb(""), BindingState.ABSENT)

    def test_the_convention_s_binding_is_satisfied(self) -> None:
        binding = mariadb_binding(mariadb_rows(SHOP))
        self.assertEqual(binding.state, BindingState.SATISFIED)
        self.assertEqual(binding.completed, MARIADB_STEPS)
        self.assertEqual(
            (binding.principal, binding.authentication, binding.character_set, binding.collation),
            ("sshop@localhost", "unix_socket", "utf8mb4", "utf8mb4_unicode_ci"),
        )
        self.assertEqual(binding.privileges, f"{', '.join(MARIADB_PRIVILEGES)} on sshop.*")

    def test_the_convention_s_statements_in_order_are_partial(self) -> None:
        for steps in (MARIADB_STEPS[:1], MARIADB_STEPS[:2]):
            with self.subTest(steps=steps):
                binding = mariadb_binding(mariadb_rows(SHOP, steps))
                self.assertEqual(binding.state, BindingState.PARTIAL)
                self.assertEqual(binding.completed, steps)

    def test_statements_out_of_order_are_custom(self) -> None:
        for steps in ((Step.DATABASE,), (Step.PRINCIPAL, Step.PRIVILEGES)):
            with self.subTest(steps=steps):
                binding = mariadb_binding(mariadb_rows(SHOP, steps))
                self.assertEqual(binding.state, BindingState.CUSTOM)

    def test_other_accounts_authentication_and_settings_are_custom(self) -> None:
        local = "U\tsshop\tlocalhost\t{}\t{}\t{}\t{}\t\t\t\t\t{}\n"
        cases = {
            "another host": mariadb_rows(SHOP)
            + f"U\tsshop\t127.0.0.1\tunix_socket\t0\t0\t\t\t\t\t\t{KEYS}\n",
            "a password": local.format("mysql_native_password", 1, 0, "", KEYS)
            + mariadb_rows(SHOP)[mariadb_rows(SHOP).index("\n") + 1 :],
            "a fallback": local.format("unix_socket", 0, 0, "", KEYS[:-1] + ', "auth_or"]'),
            "global privileges": local.format("unix_socket", 0, 1, "", KEYS),
            "resource limits": local.format(
                "unix_socket", 0, 0, 5, KEYS[:-1] + ', "max_questions"]'
            ),
            "account settings": local.format(
                "unix_socket", 0, 0, "", KEYS[:-1] + ', "password_lifetime"]'
            ),
        }
        for case, rows in cases.items():
            with self.subTest(case):
                self.assertEqual(mariadb(rows), BindingState.CUSTOM)

    def test_a_reset_resource_limit_is_the_convention_s(self) -> None:
        # ALTER USER ... WITH MAX_QUERIES_PER_HOUR 0 keeps the key, at zero.
        rows = (
            mariadb_rows(SHOP)
            .replace("unix_socket\t0\t0\t", "unix_socket\t0\t0\t0")
            .replace(KEYS, KEYS[:-1] + ', "max_questions"]')
        )
        self.assertEqual(mariadb(rows), BindingState.SATISFIED)

    def test_grants_beyond_the_convention_are_custom(self) -> None:
        full = mariadb_rows(SHOP)
        cases = {
            "a pattern grant on other databases": full + "G\tsshop\tsshop\tlocalhost\ts%\n",
            "a table grant": full + "T\tsshop\ttables_priv\t1\n",
            "a role": full + "T\tsshop\troles_mapping\t1\n",
            "a grantable privilege": full.replace("LOCK TABLES\tNO", "LOCK TABLES\tYES"),
            "fewer privileges": full.replace("R\t'sshop'@'localhost'\tsshop\tDROP\tNO\n", ""),
            "another collation": full.replace("utf8mb4_unicode_ci", "utf8mb4_uca1400_ai_ci"),
        }
        for case, rows in cases.items():
            with self.subTest(case):
                self.assertEqual(mariadb(rows), BindingState.CUSTOM)

    def test_other_accounts_grants_are_exposures_not_a_binding(self) -> None:
        pattern, table = "G\tsshop\tx\t%\ts%\n", "F\tsshop\ttables_priv\t2\n"
        for rows in (pattern, table):
            with self.subTest(rows=rows):
                binding = mariadb_binding(rows)
                self.assertEqual(binding.state, BindingState.ABSENT)
                self.assertEqual(len(binding.exposures), 1)
        binding = mariadb_binding(mariadb_rows(SHOP) + pattern + table)
        self.assertEqual(binding.state, BindingState.SATISFIED)
        self.assertIn("x@% holds privileges on databases matching s%", binding.exposures[0])
        self.assertIn("2 grants of other accounts on sshop", binding.exposures[1])

    def test_an_inactive_unix_socket_plugin_is_custom(self) -> None:
        binding = mariadb_binding(mariadb_rows(SHOP), plugin="DISABLED")
        self.assertEqual(binding.state, BindingState.CUSTOM)

    def test_a_database_directory_alone_is_custom(self) -> None:
        # MariaDB lists a data directory entry as a database.
        self.assertEqual(mariadb("S\tsshop\tutf8mb4\tutf8mb4_uca1400_ai_ci\n"), BindingState.CUSTOM)

    def test_the_catalog_read_never_selects_a_hash(self) -> None:
        sql = mariadb_catalog_sql((SHOP, BLOG))
        self.assertNotIn("JSON_VALUE(Priv,'$.authentication_string'),'')),", sql)
        self.assertIn("LENGTH(COALESCE(JSON_VALUE(Priv,'$.authentication_string'),''))>0", sql)
        self.assertNotIn("$.auth_or", sql)
        self.assertNotIn(",Priv", sql)
        self.assertNotIn("Password", sql)

    def test_only_principal_names_are_queried(self) -> None:
        for names in ((), ("root",), ("s'x",), ("sa",)):
            with self.subTest(names=names), self.assertRaises(ValueError):
                mariadb_catalog_sql(names)
            with self.subTest(names=names), self.assertRaises(ValueError):
                postgresql_catalog_sql(names)


class PostgreSQLRecognitionTests(SimpleTestCase):
    def test_nothing_under_the_name_is_absent(self) -> None:
        self.assertEqual(postgresql_binding("").state, BindingState.ABSENT)

    def test_the_convention_s_binding_is_satisfied(self) -> None:
        binding = postgresql_binding(postgresql_rows(BLOG), schema_row())
        self.assertEqual(binding.state, BindingState.SATISFIED)
        self.assertEqual(
            (binding.owner, binding.character_set, binding.collation),
            ("sblog", "UTF8", "C.UTF-8"),
        )
        self.assertEqual(binding.authentication, "peer")

    def test_the_catalog_read_never_selects_a_secret(self) -> None:
        sql = postgresql_catalog_sql((BLOG, SHOP))
        # pg_hba.conf options may hold ldapbindpasswd or a RADIUS secret, and an error
        # may quote the line.
        self.assertIn("options IS NOT NULL,error IS NOT NULL", sql)
        self.assertNotIn("options::text", sql)
        self.assertNotIn("coalesce(options", sql)
        self.assertNotIn("coalesce(error", sql)
        self.assertIn("rolpassword IS NULL", sql)
        self.assertNotIn("rolpassword,", sql)
        self.assertNotIn("setconfig", sql)

    def test_the_convention_s_statements_in_order_are_partial(self) -> None:
        for count in (1, 2, 3):
            steps = POSTGRESQL_STEPS[:count]
            schema = schema_row(steps) if Step.DATABASE in steps else None
            with self.subTest(steps=steps):
                binding = postgresql_binding(postgresql_rows(BLOG, steps), schema)
                self.assertEqual(binding.state, BindingState.PARTIAL)
                self.assertEqual(binding.completed, steps)

    def test_the_schema_revoked_before_the_database_is_custom(self) -> None:
        steps = (Step.PRINCIPAL, Step.DATABASE)
        binding = postgresql_binding(postgresql_rows(BLOG, steps), schema_row())
        self.assertEqual(binding.state, BindingState.CUSTOM)

    def test_role_powers_memberships_and_settings_are_custom(self) -> None:
        full = postgresql_rows(BLOG)
        role = "R|sblog|f|t|f|f|t|f|f|-1|t|t"
        cases = {
            "superuser": full.replace(role, "R|sblog|t|t|f|f|t|f|f|-1|t|t"),
            "createdb": full.replace(role, "R|sblog|f|t|f|t|t|f|f|-1|t|t"),
            "a password": full.replace(role, "R|sblog|f|t|f|f|t|f|f|-1|f|t"),
            "a membership": full + "M|sblog|1\n",
            "settings": full + "S|sblog|1\n",
            "database settings": full + "S|sblog|1\nS|sblog|2\n",
        }
        for case, rows in cases.items():
            with self.subTest(case):
                self.assertEqual(postgresql_binding(rows, schema_row()).state, BindingState.CUSTOM)

    def test_databases_beyond_the_convention_are_custom(self) -> None:
        full = postgresql_rows(BLOG)
        cases = {
            "another owner": full.replace("D|sblog|sblog|", "D|sblog|postgres|").replace(
                "O|sblog||pg_database|o|1\n", ""
            ),
            "an unsupported locale": full.replace("C.UTF-8|C.UTF-8", "de_DE.UTF-8|de_DE.UTF-8"),
            "an ICU locale": full.replace("|UTF8|c|", "|UTF8|i|"),
            "another grant": full.replace("{sblog=CTc/sblog}", "{sblog=CTc/sblog,x=c/sblog}"),
            "objects elsewhere": full + "O|sblog|postgres|pg_class|o|1\n",
        }
        for case, rows in cases.items():
            with self.subTest(case):
                self.assertEqual(postgresql_binding(rows, schema_row()).state, BindingState.CUSTOM)
        tables = full + "O|sblog|sblog|pg_class|o|3\n"
        self.assertEqual(postgresql_binding(tables, schema_row()).state, BindingState.SATISFIED)
        granted = (
            "N|pg_database_owner|{pg_database_owner=UC/pg_database_owner,x=U/pg_database_owner}\n"
        )
        self.assertEqual(postgresql_binding(full, granted).state, BindingState.CUSTOM)

    def test_authentication_requires_the_distribution_rules(self) -> None:
        full, schema = postgresql_rows(BLOG), schema_row()
        altered = {
            "another method": hba_rule(0, 100, "local|{sblog}|{all}|scram-sha-256|f|f"),
            "options": hba_rule(0, 100, "local|{all}|{all}|peer|t|f"),
            "a group": hba_rule(0, 100, "local|{all}|{+admins}|peer|f|f"),
            "an error": hba_rule(None, 100, "|{}|{}||f|t"),
            "an included file": hba_rule(
                0, 1, "local|{all}|{sblog}|ldap|t|f", "/etc/postgresql/16/main/extra.conf"
            ),
            "a trust rule first": hba_rule(0, 100, "local|{all}|{all}|trust|f|f"),
        }
        for case, rule in altered.items():
            with self.subTest(case):
                binding = postgresql_binding(full, schema, hba=rule + POSTGRESQL_HBA)
                self.assertEqual(binding.state, BindingState.CUSTOM)
                self.assertEqual(binding.authentication, "")
        extra = hba_rule(8, 200, "local|{replication}|{all}|peer|f|f")
        binding = postgresql_binding(full, schema, hba=POSTGRESQL_HBA + extra)
        self.assertEqual(binding.state, BindingState.CUSTOM)
        no_rules = postgresql_binding(full, schema, hba="")
        self.assertEqual((no_rules.state, no_rules.authentication), (BindingState.CUSTOM, ""))

    def test_an_edit_the_server_has_not_loaded_leaves_authentication_unknown(self) -> None:
        server = POSTGRESQL_SERVER.replace("|t\n", "|f\n")
        binding = postgresql_binding(postgresql_rows(BLOG), schema_row(), server=server)
        self.assertEqual((binding.state, binding.authentication), (BindingState.CUSTOM, ""))

    def test_a_missing_public_schema_is_custom(self) -> None:
        self.assertEqual(postgresql_binding(postgresql_rows(BLOG), "").state, BindingState.CUSTOM)


class DatabaseObservationTests(ObservationTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        add_site(self.remote, "shop", ("shop.test",))
        add_site(self.remote, "blog", ("blog.test",))
        add_site(self.remote, "wiki", ("wiki.test",))

    def as_root(self) -> None:
        self.remote.results[ROOT_QUERY] = ssh.CommandResult(0, "0\n")

    def bindings(self) -> dict[str, ObservedDatabase | None]:
        return {site.identifier: site.database for site in self.collect().sites.value}

    def test_ordinary_discovery_never_escalates(self) -> None:
        databases = self.bindings()
        for database in databases.values():
            self.assertEqual(database and database.outcome, ObservationOutcome.INACCESSIBLE)
            self.assertIn("never escalates", database.warning if database else "")
        self.assertFalse(any(c.startswith(CLIENTS) for c in self.remote.commands))

    def test_root_observes_each_site_s_binding(self) -> None:
        self.as_root()
        self.remote.catalogs.mariadb[SHOP] = mariadb_rows(SHOP)
        self.remote.catalogs.postgresql[BLOG] = postgresql_rows(BLOG)
        databases = self.bindings()
        shop, blog, wiki = databases["shop"], databases["blog"], databases["wiki"]
        self.assertEqual(
            (shop and shop.engine, shop and shop.conforms), (DatabaseEngine.MARIADB, True)
        )
        self.assertEqual(
            (blog and blog.engine, blog and blog.conforms), (DatabaseEngine.POSTGRESQL, True)
        )
        self.assertEqual(wiki and wiki.outcome, ObservationOutcome.ABSENT)
        # One read per engine for every site, and each site database's own schema.
        reads = [c for c in self.remote.commands if c.startswith(CLIENTS)]
        self.assertEqual(len(reads), 3, reads)

    def test_the_binding_matches_only_with_the_site_user_s_identity(self) -> None:
        self.as_root()
        self.remote.catalogs.mariadb[SHOP] = mariadb_rows(SHOP)
        self.remote.results["getent passwd sshop"] = ssh.CommandResult(2, "")
        shop = self.bindings()["shop"]
        self.assertEqual((shop and shop.outcome, shop and shop.conforms), ("observed", False))
        self.assertIn("site user sshop was not observed", shop.warning if shop else "")

    def test_other_accounts_grants_stop_conformance(self) -> None:
        self.as_root()
        self.remote.catalogs.mariadb[SHOP] = mariadb_rows(SHOP) + "G\tsshop\tx\t%\ts%\n"
        self.remote.catalogs.mariadb[BLOG] = "G\tsblog\tx\t%\ts%\n"
        self.remote.catalogs.postgresql[BLOG] = postgresql_rows(BLOG)
        databases = self.bindings()
        shop, blog = databases["shop"], databases["blog"]
        self.assertEqual((shop and shop.engine, shop and shop.conforms), ("mariadb", False))
        self.assertIn("x@% holds privileges", shop.warning if shop else "")
        # A pattern grant alone is not a MariaDB binding: PostgreSQL holds the blog's.
        self.assertEqual((blog and blog.engine, blog and blog.conforms), ("postgresql", False))
        self.assertIn("x@% holds privileges", blog.warning if blog else "")

    def test_the_public_schema_is_read_only_in_a_conforming_database(self) -> None:
        self.as_root()
        self.remote.catalogs.postgresql[BLOG] = postgresql_rows(BLOG).replace("|f|t|-1", "|f|f|-1")
        self.remote.catalogs.postgresql[SHOP] = postgresql_rows(SHOP)
        self.remote.catalogs.schemas[SHOP] = None
        databases = self.bindings()
        blog, shop = databases["blog"], databases["shop"]
        schema_reads = [c for c in self.remote.commands if " -d s" in c]
        self.assertEqual(len(schema_reads), 1, schema_reads)
        # A database that refuses connections no longer follows the convention; no
        # per-difference text is reported.
        self.assertEqual((blog and blog.outcome, blog and blog.conforms), ("observed", False))
        self.assertIn("does not create", blog.warning if blog else "")
        # A schema that cannot be read makes one binding custom, not the engine unsupported.
        self.assertEqual((shop and shop.outcome, shop and shop.conforms), ("observed", False))
        self.assertIn("does not create", shop.warning if shop else "")

    def test_a_stray_setting_of_another_role_counts_against_the_database_only(self) -> None:
        self.as_root()
        self.remote.catalogs.postgresql[BLOG] = postgresql_rows(BLOG) + "S|sblog|1\n"
        self.remote.catalogs.postgresql[SHOP] = postgresql_rows(SHOP)
        databases = self.bindings()
        blog, shop = databases["blog"], databases["shop"]
        self.assertFalse(blog and blog.conforms)
        self.assertTrue(shop and shop.conforms)

    def test_a_partial_binding_names_what_is_missing(self) -> None:
        self.as_root()
        self.remote.catalogs.mariadb[SHOP] = mariadb_rows(SHOP, MARIADB_STEPS[:1])
        shop = self.bindings()["shop"]
        self.assertEqual((shop and shop.outcome, shop and shop.conforms), ("observed", False))
        self.assertIn("database, privileges are missing", shop.warning if shop else "")

    def test_a_site_in_both_engines_is_unsupported(self) -> None:
        self.as_root()
        self.remote.catalogs.mariadb[SHOP] = mariadb_rows(SHOP)
        self.remote.catalogs.postgresql[SHOP] = postgresql_rows(SHOP)
        shop = self.bindings()["shop"]
        self.assertEqual(shop and shop.outcome, ObservationOutcome.UNSUPPORTED)

    def test_a_database_with_another_name_does_not_affect_a_site(self) -> None:
        self.as_root()
        self.remote.catalogs.mariadb["sother"] = mariadb_rows("sother")
        databases = self.bindings()
        self.assertEqual(databases["shop"] and databases["shop"].outcome, ObservationOutcome.ABSENT)
        self.assertNotIn("sother", " ".join(self.remote.commands))

    def test_an_engine_that_is_not_installed_holds_nothing(self) -> None:
        self.as_root()
        packages = "".join(
            f"{line}\n" for line in DPKG_OUTPUT.splitlines() if "mariadb" not in line
        )
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, packages)
        self.remote.catalogs.postgresql[BLOG] = postgresql_rows(BLOG)
        databases = self.bindings()
        self.assertEqual(databases["shop"] and databases["shop"].outcome, ObservationOutcome.ABSENT)
        self.assertTrue(databases["blog"] and databases["blog"].conforms)
        self.assertFalse(any(c.startswith(MARIADB_CLIENT) for c in self.remote.commands))

    def test_postgresql_that_is_not_installed_holds_nothing_on_any_release(self) -> None:
        self.as_root()
        packages = "".join(
            f"{line}\n" for line in DPKG_OUTPUT.splitlines() if "postgresql" not in line
        )
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, packages)
        collected = self.collect()
        unknown = replace(collected.os, outcome=ObservationOutcome.UNSUPPORTED, value=None)
        sites = collect_databases(self.remote, unknown, collected.components, collected.sites)
        wiki = {site.identifier: site.database for site in sites.value}["wiki"]
        self.assertEqual(wiki and wiki.outcome, ObservationOutcome.ABSENT)
        self.assertNotIn("not a supported release", wiki.warning if wiki else "")

    def test_a_stopped_engine_leaves_its_catalog_inaccessible(self) -> None:
        self.as_root()
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0, unit_report("mariadb.service", active="inactive", sub="dead")
        )
        self.remote.catalogs.postgresql[BLOG] = postgresql_rows(BLOG)
        databases = self.bindings()
        shop, blog = databases["shop"], databases["blog"]
        self.assertEqual(shop and shop.outcome, ObservationOutcome.INACCESSIBLE)
        self.assertIn("mariadb.service is not running", shop.warning if shop else "")
        # PostgreSQL holds the blog's binding, but MariaDB may hold another.
        self.assertEqual((blog and blog.outcome, blog and blog.conforms), ("observed", False))

    def test_a_failed_read_or_another_cluster_is_unsupported(self) -> None:
        self.as_root()
        self.remote.catalogs.failing.add("mariadb")
        self.remote.catalogs.server = POSTGRESQL_SERVER.replace("160015|", "150004|").replace(
            "/16/", "/15/"
        )
        shop = self.bindings()["shop"]
        self.assertEqual(shop and shop.outcome, ObservationOutcome.UNSUPPORTED)
        self.assertIn("root could not read the MariaDB catalog", shop.warning if shop else "")
        self.assertIn("not served by PostgreSQL 16 main", shop.warning if shop else "")

    def test_the_binding_is_shown_with_the_site(self) -> None:
        self.as_root()
        self.remote.catalogs.mariadb[SHOP] = mariadb_rows(SHOP)
        shown = {site.identifier: site for site in present_sites(self.collect().sites).sites}
        database = shown["shop"].database
        self.assertEqual(database.verdict, "MariaDB binding, as the convention requires")
        self.assertIn("Principal: sshop@localhost", database.lines)
        self.assertEqual(shown["wiki"].database.verdict, "None")
        # Only a binding that follows the convention carries its engine's connection guidance.
        self.assertEqual(shown["shop"].database_engine, DatabaseEngine.MARIADB)
        self.assertIsNone(shown["wiki"].database_engine)

    def test_a_snapshot_from_before_database_observations_says_so(self) -> None:
        sites = self.collect().sites
        shown = present_sites(replace(sites, value=(replace(sites.value[0], database=None),)))
        self.assertEqual(shown.sites[0].database.verdict, DATABASE_NOT_COLLECTED)
