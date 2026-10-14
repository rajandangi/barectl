from django.test import SimpleTestCase

from .images import foundation_inputs


class FoundationSnapshotKeyTests(SimpleTestCase):
    def test_changing_one_payload_byte_selects_a_different_snapshot(self) -> None:
        original = b"reviewed native foundation payload\n"
        self.assertNotEqual(foundation_inputs(original), foundation_inputs(original + b" "))
        self.assertEqual(foundation_inputs(original), foundation_inputs(original))
