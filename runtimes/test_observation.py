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
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].manageable, rows[0].problem)
        self.assertIn("cgi-fcgi", rows[0].extensions)
        self.assertIn(("opcache.validate_permission", "1"), rows[0].protections)
