"""The Finish's fixed reads, release comparison and body, without a server
(docs/wordpress.md#finishing-a-partial-installation).

The comparison script runs for real against synthetic archives and trees: it is the one piece
of the review that parses an archive, so its refusals are tested adversarially here. The
native behavior of the whole workflow is qualified by ``test_finish_remote``.
"""

import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Mapping
from pathlib import Path
from unittest import TestCase, mock

from bootstrap import native as bootstrap_native

from . import convention, core_native, finish_native, install_native

UID = os.getuid()
RELEASE: Mapping[str, bytes] = {
    "index.php": b"<?php // index\n",
    "wp-login.php": b"<?php // login\n",
    "wp-admin/admin.php": b"<?php // admin\n",
    "wp-includes/version.php": b"<?php $wp_version = '7.1.3';\n",
    "wp-content/index.php": b"<?php // silence\n",
    "wp-content/plugins/hello.php": b"<?php // hello\n",
}


def archive(
    files: Mapping[str, bytes],
    *,
    extra: tuple[tarfile.TarInfo, bytes] | None = None,
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        root = tarfile.TarInfo("wordpress")
        root.type, root.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(root)
        made = set()
        for path, data in files.items():
            parts = path.split("/")
            for depth in range(1, len(parts)):
                directory = "wordpress/" + "/".join(parts[:depth])
                if directory not in made:
                    made.add(directory)
                    info = tarfile.TarInfo(directory)
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                    tar.addfile(info)
            member = tarfile.TarInfo(f"wordpress/{path}")
            member.size, member.mode = len(data), 0o644
            tar.addfile(member, io.BytesIO(data))
        if extra is not None:
            tar.addfile(extra[0], io.BytesIO(extra[1]))
    return buffer.getvalue()


def place(root: Path, files: Mapping[str, bytes]) -> None:
    for path, data in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for directory, _, names in os.walk(root):
        os.chmod(directory, 0o755)  # noqa: S103 - the published modes
        for name in names:
            os.chmod(os.path.join(directory, name), 0o644)


class ComparisonScriptTests(TestCase):
    """The script exactly as the review runs it, with the pins of a synthetic archive."""

    def run_script(
        self, blob: bytes, public: Path, *, strict: bool = True, pinned: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        pinned = blob if pinned is None else pinned
        with (
            mock.patch.object(core_native, "ARCHIVE_BYTES", len(pinned)),
            mock.patch.object(core_native, "ARCHIVE_SHA256", hashlib.sha256(pinned).hexdigest()),
            mock.patch.object(core_native, "MAX_ENTRIES", 1000),
            mock.patch.object(core_native, "MAX_TREE_BYTES", 10**7),
            mock.patch.object(core_native, "MAX_FILE_BYTES", 10**6),
            mock.patch.object(core_native, "MAX_ARCHIVE_BYTES", 10**7),
        ):
            script = finish_native.compare_script()
        return subprocess.run(  # noqa: S603 - the fixed script, on temporary files
            [sys.executable, "-I", "-c", script, str(public), str(UID), "1" if strict else "0"],
            input=blob,
            capture_output=True,
            check=False,
        )

    def compared(
        self, public: Mapping[str, bytes], *, strict: bool = True, blob: bytes | None = None
    ) -> finish_native.Comparison:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            place(root, public)
            result = self.run_script(blob or archive(RELEASE), root, strict=strict)
        self.assertEqual(result.returncode, 0, result.stderr)
        return finish_native.parse_comparison(result.stdout.decode())

    def test_an_identical_release_is_the_same_everywhere(self) -> None:
        found = self.compared(RELEASE)
        self.assertEqual(set(found.tops.values()), {"same"})
        self.assertEqual((found.foreign, found.differences), ((), ()))
        self.assertEqual(
            sorted(found.tops),
            ["index.php", "wp-admin", "wp-content", "wp-includes", "wp-login.php"],
        )

    def test_missing_entries_are_absent_and_nothing_else(self) -> None:
        found = self.compared({"index.php": RELEASE["index.php"]})
        self.assertEqual(found.tops["index.php"], "same")
        self.assertEqual(
            {name: state for name, state in found.tops.items() if name != "index.php"},
            dict.fromkeys(("wp-admin", "wp-content", "wp-includes", "wp-login.php"), "absent"),
        )

    def test_an_edited_file_is_a_difference_naming_its_path(self) -> None:
        found = self.compared({**RELEASE, "wp-admin/admin.php": b"<?php evil();\n"})
        self.assertEqual(found.tops["wp-admin"], "differs")
        self.assertEqual(
            found.differences,
            (finish_native.Difference("wp-admin", "changed", "wp-admin/admin.php"),),
        )

    def test_an_extra_and_a_missing_file_inside_an_entry_differ(self) -> None:
        extra = {**RELEASE, "wp-includes/extra.php": b"x"}
        self.assertEqual(self.compared(extra).differences[0].why, "extra")
        missing = {name: data for name, data in RELEASE.items() if name != "wp-admin/admin.php"}
        found = self.compared({**missing, "wp-admin/other.php": b"x"})
        self.assertEqual(found.tops["wp-admin"], "differs")

    def test_content_the_operator_added_to_wp_content_differs_only_for_a_first_installation(
        self,
    ) -> None:
        added = {**RELEASE, "wp-content/uploads/a.jpg": b"jpg"}
        self.assertEqual(self.compared(added, strict=True).tops["wp-content"], "differs")
        self.assertEqual(self.compared(added, strict=False).tops["wp-content"], "content")
        edited = {**RELEASE, "wp-content/plugins/hello.php": b"changed"}
        self.assertEqual(self.compared(edited, strict=False).tops["wp-content"], "content")

    def test_a_file_in_place_of_wp_content_is_never_content(self) -> None:
        public = {name: data for name, data in RELEASE.items() if not name.startswith("wp-content")}
        found = self.compared({**public, "wp-content": b"not a directory"}, strict=False)
        self.assertEqual(found.tops["wp-content"], "differs")

    def test_entries_beyond_the_release_are_foreign_except_the_loader_and_placeholder(self) -> None:
        public = {
            **RELEASE,
            "wp-config.php": b"<?php\n",
            "index.html": b"<html>",
            "robots.txt": b"x",
            ".htaccess": b"x",
        }
        self.assertEqual(self.compared(public).foreign, (".htaccess", "robots.txt"))

    def test_a_link_is_a_difference_and_is_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            place(root, RELEASE)
            outside = root.parent / "outside-secret"
            outside.write_text("secret")
            self.addCleanup(outside.unlink)
            (root / "wp-admin" / "link.php").symlink_to(outside)
            result = self.run_script(archive(RELEASE), root)
        found = finish_native.parse_comparison(result.stdout.decode())
        self.assertEqual(found.tops["wp-admin"], "differs")
        self.assertNotIn("secret", result.stdout.decode())

    def test_other_modes_and_hard_links_differ(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            place(root, RELEASE)
            os.chmod(root / "index.php", 0o666)  # noqa: S103 - the test edits a mode
            os.link(root / "wp-login.php", root / "wp-login-copy.php")
            found = finish_native.parse_comparison(
                self.run_script(archive(RELEASE), root).stdout.decode()
            )
        self.assertEqual(found.tops["index.php"], "differs")
        self.assertEqual(found.tops["wp-login.php"], "differs")
        self.assertEqual(found.foreign, ("wp-login-copy.php",))

    def test_an_unsafe_name_is_reported_without_being_printed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            place(root, RELEASE)
            (root / "wp-admin" / "bad name$(id).php").write_bytes(b"x")
            (root / "bad name").write_bytes(b"x")
            result = self.run_script(archive(RELEASE), root)
        text = result.stdout.decode()
        self.assertNotIn("bad name", text)
        found = finish_native.parse_comparison(text)
        self.assertEqual(found.tops["wp-admin"], "differs")
        self.assertEqual(found.foreign, ("?",))

    def test_an_archive_that_is_not_the_pin_prints_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            place(root, RELEASE)
            blob = archive(RELEASE)
            for name, (stream, pin) in {
                "other bytes": (blob + b"x", blob),
                "truncated": (blob[:-20], blob),
                "other archive": (archive({"index.php": b"other"}), blob),
                "not an archive": (b"<html>captive portal</html>", blob),
                "empty": (b"", blob),
            }.items():
                with self.subTest(name):
                    result = self.run_script(stream, root, pinned=pin)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")

    def test_members_the_installation_would_refuse_are_refused_here_too(self) -> None:
        link = tarfile.TarInfo("wordpress/evil")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        traversal = tarfile.TarInfo("wordpress/../evil.php")
        traversal.size = 1
        foreign_prefix = tarfile.TarInfo("other/index.php")
        foreign_prefix.size = 1
        device = tarfile.TarInfo("wordpress/dev")
        device.type = tarfile.CHRTYPE
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            place(root, RELEASE)
            for name, member in {
                "link": (link, b""),
                "traversal": (traversal, b"x"),
                "prefix": (foreign_prefix, b"x"),
                "device": (device, b""),
            }.items():
                with self.subTest(name):
                    result = self.run_script(archive(RELEASE, extra=member), root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")

    def test_limits_stop_the_comparison(self) -> None:
        big = {"index.php": b"x" * 2000}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            place(root, big)
            blob = archive(big)
            with (
                mock.patch.object(core_native, "MAX_FILE_BYTES", 1000),
                mock.patch.object(core_native, "ARCHIVE_BYTES", len(blob)),
                mock.patch.object(core_native, "ARCHIVE_SHA256", hashlib.sha256(blob).hexdigest()),
            ):
                script = finish_native.compare_script()
            result = subprocess.run(  # noqa: S603 - the fixed script, on temporary files
                [sys.executable, "-I", "-c", script, str(root), str(UID), "1"],
                input=blob,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


class ParsingTests(TestCase):
    def test_the_comparison_must_be_complete_and_exact(self) -> None:
        good = "tops 1\ntop index.php same\nend\n"
        self.assertEqual(finish_native.parse_comparison(good).tops, {"index.php": "same"})
        for bad in (
            "",
            "tops 1\ntop index.php same\n",
            "tops 2\ntop index.php same\nend\n",
            "tops 1\ntop index.php maybe\nend\n",
            "tops 1\ntop index.php same\nend\nextra\n",
            "tops 1\ntop bad;name same\nend\n",
            "tops 1\ntop index.php same\ndiff index.php changed $(id)\nend\n",
            "top index.php same\nend\n",
            "tops 1\ntops 1\ntop index.php same\nend\n",
        ):
            with self.subTest(bad=bad), self.assertRaises(finish_native.Unreadable):
                finish_native.parse_comparison(bad)

    def test_the_digest_ignores_only_trailing_newlines_like_command_substitution(self) -> None:
        text = "tops 1\ntop index.php same\nend\n"
        self.assertEqual(
            finish_native.comparison_digest(text), hashlib.sha256(text[:-1].encode()).hexdigest()
        )
        self.assertEqual(
            finish_native.comparison_digest(text), finish_native.comparison_digest(text + "\n")
        )

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
        for build in (
            finish_native.layout_argv,
            finish_native.database_state_argv,
            lambda identifier: finish_native.stream_argv(identifier, 1000, strict=True),
        ):
            for identifier in ("", "a", "UPPER", "shop; id", "../etc", "x" * 30):
                with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                    build(identifier)
        with self.assertRaises(ValueError):
            finish_native.stream_argv("shop", 0, strict=True)


class ReadsTests(TestCase):
    def test_the_reads_never_write_start_application_code_or_name_a_secret(self) -> None:
        reads = [
            *finish_native.layout_argv("shop"),
            *finish_native.database_state_argv("shop"),
            *finish_native.stream_argv("shop", 1003, strict=True),
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

    def test_the_archive_read_is_pinned_bounded_and_over_https_only(self) -> None:
        text = " ".join(finish_native.stream_argv("shop", 1003, strict=False))
        for required in (
            "--proto =https",
            "--proto-redir =https",
            f"--max-filesize {core_native.MAX_ARCHIVE_BYTES}",
            "--max-time 12",
            core_native.ARCHIVE_URL,
            core_native.ARCHIVE_SHA256,
            str(core_native.ARCHIVE_BYTES),
            "/var/www/shop/public 1003 0",
        ):
            self.assertIn(required, text)
        self.assertNotIn("--insecure", text)
        self.assertNotIn("-k ", text)

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
