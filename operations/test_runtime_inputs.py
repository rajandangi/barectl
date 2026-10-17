"""Site runtime selections freeze an identifier without inventing DNS inputs."""

import unittest

from .inputs import InputShape, decode_inputs


class SiteRuntimeInputTests(unittest.TestCase):
    def test_site_selection_round_trips_without_dns_names(self) -> None:
        document: dict[str, object] = {"version": 1, "selection": "nodejs_24", "identifier": "shop"}
        inputs = decode_inputs(document, ("nodejs_22", "nodejs_24"), InputShape.SITE_RUNTIME)
        self.assertEqual(inputs.document(), document)
        self.assertEqual(inputs.names, ())

    def test_invalid_or_excess_site_runtime_fields_are_refused(self) -> None:
        document: dict[str, object] = {"version": 1, "selection": "nodejs_24", "identifier": "shop"}
        for changed in (
            {"version": True},
            {"identifier": "../shop"},
            {"identifier": "repo"},
            {"selection": "nodejs_26"},
            {"names": ["shop.example.com"]},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                decode_inputs(document | changed, ("nodejs_24",), InputShape.SITE_RUNTIME)
