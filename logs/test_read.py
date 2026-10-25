"""The server-side bounded, scrubbed log page (Phase C #389)."""

import json
import os
import pathlib
import tempfile
from typing import cast, override

from django.test import SimpleTestCase

from logs.bodies import read

CANARY = "canary-secret-4f1d0c2a9b"


class LogReadTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        root = self.enterContext(tempfile.TemporaryDirectory())
        self.root = pathlib.Path(root)
        self.directory = self.root / "alpha" / "logs"
        self.directory.mkdir(parents=True)
        (self.root / "alpha" / "private" / "storage" / "logs").mkdir(parents=True)

    def write(self, name: str, text: str) -> str:
        path = self.directory / name
        path.write_text(text)
        return str(path)

    def page(
        self,
        source: str = "php_errors",
        *,
        term: str = "",
        since: str = "",
        until: str = "",
        cursor: str = "",
    ) -> dict[str, object]:
        return read.read_page(
            "alpha",
            source,
            root=str(self.root),
            term=term,
            since=since,
            until=until,
            cursor=cursor,
        )

    def lines(self, page: dict[str, object]) -> list[dict[str, object]]:
        value = page["lines"]
        if not isinstance(value, list):
            raise AssertionError("The page has no line list.")
        return cast(list[dict[str, object]], value)

    def files(self, page: dict[str, object]) -> list[object]:
        value = page["files"]
        if not isinstance(value, list):
            raise AssertionError("The page has no file list.")
        return cast(list[object], value)

    def raws(self, page: dict[str, object]) -> list[str]:
        return [str(line["raw"]) for line in self.lines(page)]

    def test_a_page_holds_the_newest_lines_in_file_order_with_an_older_cursor(self) -> None:
        self.write(
            "php-error.log",
            "".join(f"line {number:04d} {'x' * 40}\n" for number in range(700)),
        )
        newest = self.page()
        self.assertEqual(newest["state"], "observed")
        self.assertEqual(len(self.lines(newest)), read.MAX_LINES)
        self.assertEqual(self.raws(newest)[-1].split()[1], "0699")
        self.assertFalse(newest["at_end"])
        older = self.page(cursor=str(newest["cursor"]))
        self.assertEqual(older["state"], "observed")
        self.assertEqual(self.raws(older)[-1].split()[1], "0199")

    def test_a_page_is_at_most_five_hundred_lines_and_forty_eight_kibibytes(self) -> None:
        self.write(
            "php-slow.log", "".join(f"line {number:04d} {'x' * 200}\n" for number in range(900))
        )
        page = self.page("php_slow")
        self.assertLessEqual(len(self.lines(page)), read.MAX_LINES)
        self.assertLessEqual(int(str(page["bytes"])), read.MAX_PAGE_BYTES)
        self.assertEqual(self.raws(page)[-1].split()[1], "0899")

    def test_a_single_huge_line_is_truncated_not_stored_whole(self) -> None:
        self.write("php-error.log", "first\n" + "z" * 20_000 + "\n")
        page = self.page()
        self.assertEqual(len(self.lines(page)), 2)
        self.assertTrue(self.lines(page)[-1]["truncated"])
        self.assertEqual(len(str(self.lines(page)[-1]["raw"])), read.MAX_LINE_BYTES)

    def test_a_missing_empty_and_unreadable_log_are_described_separately(self) -> None:
        missing = self.page()
        self.assertEqual(missing["state"], "missing")
        self.write("php-error.log", "")
        self.assertEqual(self.page()["state"], "empty")
        (self.directory / "php-error.log").unlink()
        (self.directory / "php-error.log").mkdir()
        unreadable = self.page()
        self.assertEqual(unreadable["state"], "unreadable")
        self.assertIn("not a regular file", str(unreadable["note"]))

    def test_a_cursor_into_a_rotated_file_reports_rotation(self) -> None:
        path = self.write(
            "php-error.log", "".join(f"old line {number:04d} {'x' * 40}\n" for number in range(600))
        )
        cursor = self.page()["cursor"]
        self.assertTrue(cursor)
        os.replace(path, path + ".1.gz")
        pathlib.Path(path).write_text("new one\n")
        rotated = self.page(cursor=str(cursor))
        self.assertEqual(rotated["state"], "rotated")
        self.assertIn("rotated since", str(rotated["note"]))

    def test_secret_values_from_the_private_environment_and_wordpress_config_are_replaced(
        self,
    ) -> None:
        private = self.root / "alpha" / "private"
        for name, text in (
            (
                "laravel.env",
                f"APP_KEY=base64:{CANARY}\nDB_PASSWORD=\nAPP_ENV=production\n",
            ),
            (
                "wp-config.php",
                (
                    "<?php\n"
                    "define( 'DB_PASSWORD', 'canary-database-8a7c' );\n"
                    "define( 'AUTH_KEY', 'canary-salt-2d9e' );\n"
                    "define( 'DB_NAME', 'salpha' );\n"
                ),
            ),
        ):
            path = private / name
            path.write_text(text)
            path.chmod(0o600)
        self.write(
            "php-error.log",
            (
                f"warning login base64:{CANARY} from canary-database-8a7c "
                "salt canary-salt-2d9e\nsecond line sa lpha\n"
            ),
        )
        page = self.page()
        stored = json.dumps(page)
        for canary in (CANARY, "canary-database-8a7c", "canary-salt-2d9e"):
            self.assertNotIn(canary, stored)
        self.assertIn(read.REDACTED, stored)
        # A non-secret constant's value is not treated as a secret.
        self.assertIn("sa lpha", stored)

    def test_a_plain_search_term_and_a_time_range_select_the_matching_lines(self) -> None:
        self.write(
            "php-error.log",
            "[25-Oct-2026 10:00:00 UTC] first warning\n"
            "[25-Oct-2026 11:00:00 UTC] second warning\n"
            "[25-Oct-2026 12:00:00 UTC] unrelated\n",
        )
        self.assertEqual(len(self.lines(self.page(term="WARNING"))), 2)
        ranged = self.page(
            since="2026-10-25T10:30:00",
            until="2026-10-25T11:30:00",
        )
        self.assertEqual(self.raws(ranged), ["[25-Oct-2026 11:00:00 UTC] second warning"])

    def test_an_access_line_renders_time_method_path_status_and_duration(self) -> None:
        self.write(
            "access.json",
            json.dumps(
                {
                    "ts": 1_793_000_000.25,
                    "request": {"method": "GET", "uri": "/hello.txt?key=REDACTED"},
                    "status": 200,
                    "duration": 0.025,
                }
            )
            + "\n",
        )
        line = self.lines(self.page("visits"))[0]
        self.assertEqual(line["method"], "GET")
        self.assertEqual(line["path"], "/hello.txt?key=REDACTED")
        self.assertEqual(line["status"], 200)
        self.assertEqual(line["duration"], "25 ms")
        self.assertTrue(line["time"])
        self.assertIn("hello.txt", str(line["raw"]))

    def test_a_laravel_daily_log_is_read_from_shared_private_storage(self) -> None:
        logs = self.root / "alpha" / "private" / "storage" / "logs"
        (logs / "laravel-2026-10-24.log").write_text("older\n")
        (logs / "laravel-2026-10-25.log").write_text("newest\n")
        page = self.page("application")
        self.assertEqual(page["state"], "observed")
        self.assertEqual(self.raws(page), ["newest"])
        self.assertEqual(len(self.files(page)), 2)

    def test_a_wordpress_debug_log_is_missing_until_it_is_created(self) -> None:
        self.assertEqual(self.page("wordpress")["state"], "missing")
        self.write("wp-debug.log", "PHP notice\n")
        self.assertEqual(self.raws(self.page("wordpress")), ["PHP notice"])
