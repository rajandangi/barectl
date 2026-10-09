"""The application convention's grammar, run for real against files on this machine."""

import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import override

from django.test import SimpleTestCase

from discovery.models import CoreQualification

from .convention import (
    CORE_TABLES,
    SALTS,
    CatalogFormatError,
    FileInspection,
    inspection_command,
    options_sql,
    parse_inspection,
    parse_options,
    parse_schema,
    qualification,
    render_loader,
    render_private_configuration,
    schema_sql,
)

SALT_VALUES = tuple(f"{chr(97 + n) * 20}!#$%&()*+,-./:;<=>?@[]^_`{{|}}~"[:64] for n in range(8))


class FixedReadTests(SimpleTestCase):
    """The server-side script is executed here against a temporary tree, as it runs there."""

    @override
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        (self.base / "shop" / "public" / "wp-includes").mkdir(parents=True)
        (self.base / "shop" / "private").mkdir()

    def read(self, identifier: str = "shop") -> FileInspection:
        command = shlex.split(inspection_command(identifier, base=str(self.base)))
        result = subprocess.run(  # noqa: S603 - the fixed script under test
            [sys.executable, *command[1:]], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.stderr, "")
        inspected = parse_inspection(result.stdout)
        if inspected is None:
            self.fail(result.stdout)
        return inspected

    def write(self, relative: str, text: str) -> Path:
        path = self.base / "shop" / relative
        path.write_text(text.replace("/var/www", str(self.base)))
        return path

    def test_nothing_on_the_server_is_absent_evidence(self) -> None:
        self.assertEqual(self.read(), FileInspection("absent", "absent", "", "none"))

    def test_the_documented_files_are_recognized_with_a_digest_and_the_version_literal(
        self,
    ) -> None:
        text = render_private_configuration("shop", SALT_VALUES)
        self.write("private/wp-config.php", text)
        self.write("public/wp-config.php", render_loader("shop"))
        self.write("public/wp-includes/version.php", "<?php\n$wp_version = '7.1.3';\n")
        inspected = self.read()
        self.assertEqual(inspected.configuration, "supported")
        self.assertEqual(inspected.version, "7.1.3")
        self.assertEqual(len(inspected.configuration_digest), 64)
        self.assertEqual(inspected.loader, "exact")

    def test_the_loader_is_exact_or_other(self) -> None:
        for text, expected in (
            (render_loader("shop"), "exact"),
            (render_loader("shop") + "\n", "other"),
            (render_loader("shop").replace("require_once", "include_once"), "other"),
            ("<?php\nrequire '/etc/passwd';\n", "other"),
        ):
            self.write("public/wp-config.php", text)
            self.assertEqual(self.read().loader, expected)

    def test_hostile_configuration_is_data_and_never_evaluated(self) -> None:
        marker = self.base / "executed"
        hostile = (
            f"<?php file_put_contents({str(marker)!r}, 'x'); ?>\n",
            render_private_configuration("shop", SALT_VALUES).replace(
                "$table_prefix", f"system('touch {marker}'); $table_prefix"
            ),
            render_private_configuration("shop", SALT_VALUES)
            + "define( 'WP_ALLOW_MULTISITE', true );\n",
            render_private_configuration("shop", SALT_VALUES).replace("wp_", "evil_"),
            render_private_configuration("shop", SALT_VALUES).replace("utf8mb4", "latin1"),
            render_private_configuration("shop", SALT_VALUES).replace("\n", "\r\n"),
            render_private_configuration("shop", SALT_VALUES).replace("sshop", "sother"),
        )
        for text in hostile:
            self.write("private/wp-config.php", text)
            inspected = self.read()
            self.assertEqual(inspected.configuration, "unsupported")
            self.assertEqual(inspected.configuration_digest, "")
            self.assertGreater(inspected.line, 0)
        self.assertFalse(marker.exists())

    def test_a_configuration_with_a_database_password_is_unsupported(self) -> None:
        text = render_private_configuration("shop", SALT_VALUES).replace(
            "DB_PASSWORD', ''", "DB_PASSWORD', 'secret'"
        )
        self.write("private/wp-config.php", text)
        self.assertEqual(self.read().configuration, "unsupported")

    def test_symbolic_links_oversize_files_and_non_files_are_other(self) -> None:
        target = self.base / "elsewhere"
        target.write_text(render_private_configuration("shop", SALT_VALUES))
        os.symlink(target, self.base / "shop" / "private" / "wp-config.php")
        (self.base / "shop" / "public" / "wp-config.php").mkdir()
        self.write("public/wp-includes/version.php", "# " + "x" * 9000)
        self.assertEqual(self.read(), FileInspection("other", "other", "", "other"))

    def test_the_version_literal_must_be_one_plain_assignment(self) -> None:
        for text, expected in (
            ("<?php\n$wp_version = '7.1.3';\n$wp_db_version = 60717;\n", "7.1.3"),
            ("<?php\n$wp_version = '7.2-beta1';\n", "7.2-beta1"),
            ("<?php\n$wp_version = '7.1.3';\n$wp_version = '9.9';\n", "unparseable"),
            ("<?php\n$wp_version = $other;\n", "unparseable"),
            ("<?php\n  $wp_version = '7.1.3';\n", "unparseable"),
        ):
            self.write("public/wp-includes/version.php", text)
            self.assertEqual(self.read().version, expected, text)

    def test_unreadable_files_are_denied_not_absent(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root reads every file")
        path = self.write("private/wp-config.php", "x")
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        self.assertEqual(self.read().configuration, "denied")

    def test_other_output_is_not_parsed(self) -> None:
        for output in (
            "",
            "loader exact\nconfiguration supported\nversion 7.1.3\n",
            "loader exact\nloader exact\nconfiguration absent\nversion none\n",
            "loader exact\nconfiguration absent\nversion none\nextra 1\n",
            "loader exact\nconfiguration absent\ndigest " + "0" * 64 + "\nversion none\n",
            "loader bogus\nconfiguration absent\nversion none\n",
        ):
            self.assertIsNone(parse_inspection(output), output)

    def test_a_non_identifier_is_refused_before_a_command_exists(self) -> None:
        with self.assertRaises(ValueError):
            inspection_command("../etc")


class RenderedFileTests(SimpleTestCase):
    def test_the_private_configuration_is_the_documented_grammar(self) -> None:
        text = render_private_configuration("shop", SALT_VALUES)
        lines = text.splitlines()
        self.assertEqual(lines[0], "<?php")
        self.assertEqual(lines[2], "\tdefine( 'ABSPATH', '/var/www/shop/public/' );")
        self.assertIn("define( 'DB_HOST', 'localhost:/run/mysqld/mysqld.sock' );", lines)
        self.assertIn("define( 'DB_PASSWORD', '' );", lines)
        self.assertEqual(lines[-1], "$table_prefix = 'wp_';")
        for key in SALTS:
            self.assertEqual(sum(line.startswith(f"define( '{key}'") for line in lines), 1)
        with self.assertRaises(ValueError):
            render_private_configuration("shop", ("short",) * 8)
        with self.assertRaises(ValueError):
            render_private_configuration("shop", ("a'b" * 20,) * 8)

    def test_the_loader_is_the_documented_three_statements(self) -> None:
        self.assertEqual(
            render_loader("shop"),
            "<?php\nrequire '/var/www/shop/private/wp-config.php';\n"
            "require_once ABSPATH . 'wp-settings.php';\n",
        )


class VersionTests(SimpleTestCase):
    def test_the_observed_release_is_compared_with_the_qualified_one(self) -> None:
        for version, expected in (
            ("7.1.3", CoreQualification.QUALIFIED),
            ("7.1.4", CoreQualification.NEWER),
            ("7.2", CoreQualification.NEWER),
            ("8.0.0", CoreQualification.NEWER),
            ("7.1.2", CoreQualification.OLDER),
            ("6.9", CoreQualification.OLDER),
            ("7.2-beta1", CoreQualification.UNRECOGNIZED),
            ("trunk", CoreQualification.UNRECOGNIZED),
        ):
            self.assertEqual(qualification(version), expected, version)


class CatalogTests(SimpleTestCase):
    def test_the_schema_read_names_tables_and_columns_but_reads_no_row(self) -> None:
        sql = schema_sql(["sshop", "sblog"])
        self.assertIn("'sshop','sblog'", sql)
        self.assertIn("information_schema.COLUMNS", sql)
        lowered = sql.lower()
        for word in ("mysql.", "from `", "insert", "update ", "delete"):
            self.assertNotIn(word, lowered)
        with self.assertRaises(ValueError):
            schema_sql(["sshop'; DROP DATABASE x; --"])

    def test_the_options_read_is_bounded_to_the_two_canonical_options(self) -> None:
        sql = options_sql("sshop")
        self.assertIn("`sshop`.`wp_options`", sql)
        self.assertIn("option_name IN ('siteurl','home')", sql)
        self.assertIn("LEFT(option_value,201)", sql)
        with self.assertRaises(ValueError):
            options_sql("sshop`; --")

    def test_schema_rows_are_summarized_per_database(self) -> None:
        complete = "".join(
            f"C\tsshop\twp_{table}\t{len(names)}\n" for table, names in CORE_TABLES.items()
        )
        output = (
            complete
            + f"W\tsshop\t{len(CORE_TABLES)}\nX\tsblog\t1\nW\tsblog\t3\nC\tsblog\twp_users\t2\n"
        )
        parsed = parse_schema(output, ["sshop", "sblog", "sempty"])
        self.assertTrue(parsed["sshop"].complete)
        self.assertFalse(parsed["sshop"].ambiguous)
        self.assertEqual((parsed["sblog"].tables, parsed["sblog"].complete), (3, False))
        self.assertTrue(parsed["sblog"].ambiguous)
        self.assertEqual((parsed["sempty"].tables, parsed["sempty"].complete), (0, False))
        for bad in ("C\tsshop\twp_unknown\t1\n", "W\tother\t1\n", "Z\tsshop\n"):
            with self.assertRaises(CatalogFormatError):
                parse_schema(bad, ["sshop"])

    def test_options_must_be_plain_urls(self) -> None:
        self.assertEqual(
            parse_options("home\thttps://a.example\nsiteurl\thttps://a.example\n"),
            {"home": "https://a.example", "siteurl": "https://a.example"},
        )
        self.assertEqual(parse_options("home\tjavascript:x\n"), {"home": ""})
        for bad in ("blogname\tx\n", "home\ta\tb\n"):
            with self.assertRaises(CatalogFormatError):
                parse_options(bad)
