"""Sealing, opening and scrubbing for the confidential input channel
(docs/adr/0032-keep-secrets-in-private-native-files.md)."""

import tempfile
from pathlib import Path
from typing import override

from django.test import SimpleTestCase, override_settings

from operations import confidential

CANARY = "barectl-canary-4f1d0c2a9b6e"


class ConfidentialChannelTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            override_settings(CONFIDENTIAL_KEY_PATH=str(directory / "confidential.key"))
        )
        confidential.reset()
        self.addCleanup(confidential.reset)

    def test_a_value_round_trips(self) -> None:
        sealed = confidential.seal(CANARY.encode())
        self.assertNotIn(CANARY, sealed)
        self.assertEqual(confidential.unseal(sealed), CANARY.encode())

    def test_a_rotated_key_cannot_open_an_earlier_value(self) -> None:
        sealed = confidential.seal(CANARY.encode())
        # A worker process start replaces the key, so the value is no longer readable.
        confidential.rotate()
        self.assertIsNone(confidential.unseal(sealed))

    def test_a_malformed_value_opens_to_none(self) -> None:
        for value in ("", "not base64!", confidential.seal(CANARY.encode())[:-2]):
            with self.subTest(value=value):
                self.assertIsNone(confidential.unseal(value))

    def test_sealing_rejects_empty_oversized_and_nul_values(self) -> None:
        for value in (b"", b"\0", b"x" * (confidential.MAX_SECRET_BYTES + 1)):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                confidential.seal(value)

    def test_scrub_replaces_every_known_value(self) -> None:
        text = f"output {CANARY} and {CANARY}"
        self.assertEqual(
            confidential.scrub(text, (CANARY, "other")),
            "output <secret> and <secret>",
        )
