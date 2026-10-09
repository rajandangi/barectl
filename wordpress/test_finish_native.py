"""The Finish's fixed reads, parsers and body, without a server
(docs/wordpress.md#finishing-a-partial-installation).

The native behavior of the whole workflow, including the run's comparison of existing release
files with its staged copy, is qualified by ``test_finish_remote``.
"""

from unittest import TestCase

from bootstrap import native as bootstrap_native

from . import convention, core_native, finish_native, install_native


class ParsingTests(TestCase):
    def test_the_database_read_needs_every_part_once(self) -> None:
        counts = "S\t1\nT\t0\nR\t0\nE\t0\nG\t0\n"
        good = f"part counts\n{counts}part schema\npart options\n"
        facts = finish_native.parse_database(good, "shop")
        self.assertTrue(facts.counts.empty)
        self.assertFalse(facts.installed)
        for bad in (
            "",
            f"part counts\n{counts}part schema\n",
            f"{counts}part counts\n",
            f"part counts\n{counts}part counts\n{counts}part schema\npart options\n",
            f"part counts\n{counts}part schema\nJUNK\npart options\n",
            "part counts\nS\t1\npart schema\npart options\n",
            f"part counts\n{counts}part schema\npart options\nname\tvalue\n",
        ):
            with self.subTest(bad=bad), self.assertRaises(finish_native.Unreadable):
                finish_native.parse_database(bad, "shop")

    def test_the_layout_needs_the_trees_and_the_inspection(self) -> None:
        trees = "site d 750 1 1 2 4096 public\nend site\nend public\nend private\n"
        inspection = "inspect loader absent\ninspect configuration absent\ninspect version none\n"
        layout = finish_native.parse_layout(trees + inspection)
        self.assertTrue(layout.files.complete)
        self.assertEqual(layout.inspection.loader, "absent")
        self.assertFalse(finish_native.parse_layout(inspection).files.complete)
        for bad in (trees, trees + "inspect loader absent\n", trees + "junk\n"):
            with self.subTest(bad=bad), self.assertRaises(finish_native.Unreadable):
                finish_native.parse_layout(bad)

    def test_identifiers_are_checked_before_any_script_is_built(self) -> None:
        for build in (finish_native.layout_argv, finish_native.database_state_argv):
            for identifier in ("", "a", "UPPER", "shop; id", "../etc", "x" * 30):
                with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                    build(identifier)


class ReadsTests(TestCase):
    def test_the_reads_never_write_start_application_code_or_name_a_secret(self) -> None:
        reads = [
            *finish_native.layout_argv("shop"),
            *finish_native.database_state_argv("shop"),
        ]
        text = "\n".join(reads)
        for forbidden in (
            "wp-cli",
            "/usr/bin/php",
            "--allow-root",
            "> /",
            "rm ",
            "chown",
            "chmod",
            "DELETE",
            "INSERT",
            "UPDATE ",
            "SELECT * ",
        ):
            self.assertFalse(forbidden in text, forbidden)
        # The only table row the reads select is a canonical option, bounded to 201 characters.
        self.assertIn("LEFT(option_value,201)", text)
        self.assertIn("SET SESSION TRANSACTION READ ONLY", text)

    def test_the_two_forms_of_a_read_report_the_same_text(self) -> None:
        # The review hashes the read's output as the lock does, so the lock's inline form,
        # which calls the functions the body defines, runs the same fixed commands.
        identifier, database = "shop", "sshop"
        sq, oq = convention.schema_command([database]), convention.options_command(database)
        full = finish_native._database_text(identifier, sq, oq)
        inline = finish_native._database_text(identifier, "sq", "oq")
        self.assertEqual(full.replace(sq, "sq").replace(oq, "oq"), inline)
        inspection = convention.inspection_command(identifier)
        self.assertEqual(
            finish_native._layout_text(identifier, inspection).replace(inspection, "ins"),
            finish_native._layout_text(identifier, "ins"),
        )


class ExitTests(TestCase):
    def test_the_finish_status_is_its_own_and_the_rest_are_the_installations(self) -> None:
        installation = {
            value for name, value in vars(install_native.Exit).items() if name.isupper()
        }
        self.assertNotIn(finish_native.Exit.NOT_GATED, installation)
        self.assertNotIn(
            finish_native.Exit.NOT_GATED, {int(item) for item in bootstrap_native.Exit}
        )
        self.assertEqual(finish_native.Exit.DRIFT, bootstrap_native.Exit.DRIFT)
        self.assertEqual(finish_native.Exit.READY, install_native.Exit.READY)


class ReleaseEntriesTests(TestCase):
    def test_the_pinned_release_has_the_kinds_the_comparison_expects(self) -> None:
        entries = core_native.RELEASE_ENTRIES
        self.assertEqual(len(entries), 19)
        self.assertEqual(
            sorted(name for name, kind in entries.items() if kind == "d"),
            ["wp-admin", "wp-content", "wp-includes"],
        )
        for name in entries:
            self.assertRegex(name, r"^[a-z0-9.-]+$")
        self.assertNotIn("wp-config.php", entries)
        self.assertNotIn("index.html", entries)
