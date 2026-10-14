import json
from pathlib import Path

from django.test import SimpleTestCase

from .catalog import Architecture
from .observation import observations


class LiveMasterObservationTests(SimpleTestCase):
    def test_real_fpm_extension_names_are_accepted_and_live_protections_are_shown(self) -> None:
        value = json.loads(
            Path(__file__).with_name("fixtures").joinpath("php84-native-read.json").read_text()
        )
        rows = observations(value["runtimes"], Architecture.AARCH64)
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[0].manageable, rows[0].problem)
        self.assertIn("cgi-fcgi", rows[0].extensions)
        self.assertIn(("opcache.validate_permission", "1"), rows[0].protections)

    def test_live_response_requires_an_integer_schema_version(self) -> None:
        value = json.loads(
            Path(__file__).with_name("fixtures").joinpath("php84-native-read.json").read_text()
        )
        row = value["runtimes"][0]
        header, body = row["response"].split("\r\n\r\n")
        original = json.loads(body)
        for version in (True, 1.0, "1"):
            with self.subTest(version=version):
                row["response"] = header + "\r\n\r\n" + json.dumps({**original, "version": version})
                self.assertFalse(observations([row], Architecture.AARCH64)[0].manageable)

    def test_a_foreign_running_executable_is_not_adopted_from_matching_disk_files(self) -> None:
        value = json.loads(
            Path(__file__).with_name("fixtures").joinpath("php84-native-read.json").read_text()
        )
        row = value["runtimes"][0]
        row["master_executable"] = "/usr/local/lib/foreign-php-fpm"
        result = observations([row], Architecture.AARCH64)
        self.assertFalse(result[0].manageable)
        self.assertIn("Pool changes", result[0].problem)
