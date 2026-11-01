"""Capture provenance at the recorder boundary, without inventing server output."""

import json
import tempfile
from pathlib import Path
from typing import override
from unittest import mock

from django.test import SimpleTestCase

from . import recorded, source_manifest
from . import transcript_provenance as provenance


class CaptureSelectionTests(SimpleTestCase):
    def test_audited_unsupported_host_does_not_consume_sign_in_body(self) -> None:
        self.assertTrue(provenance.audited_exclusion())
        states = ("ubuntu-24.04", "foundation-26.04")
        before = {provenance.OMITTED: "old", "security/sign_in.py": "same"}
        after = {**before, provenance.OMITTED: "new"}
        self.assertEqual(
            provenance.affected(states, before, after, proof=True), ("foundation-26.04",)
        )
        self.assertEqual(provenance.affected(states, before, after, proof=False), states)
        self.assertEqual(provenance.affected(states, before, before, proof=True), ())
        for changed in (
            "security/sign_in.py",
            "disposable/images.py",
            "docker/disposable-server/Dockerfile",
        ):
            with self.subTest(changed=changed):
                self.assertEqual(
                    provenance.affected(states, before, {**after, changed: "new"}, proof=True),
                    states,
                )

    def test_legacy_manifest_without_receipts_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(json.dumps({"version": 1, "sources": source_manifest.digests()}))
            with mock.patch.object(source_manifest, "MANIFEST", manifest):
                self.assertEqual(
                    source_manifest.stale(),
                    tuple(f"capture:{state}" for state in recorded.stored()),
                )

    def test_real_recorded_states_select_only_affected_captures(self) -> None:
        states = recorded.stored()
        current = provenance.inputs()
        metadata = {
            "capture_inputs": {**current, provenance.OMITTED: "0" * 64},
            "capture_pins": recorded.current_pins(),
            "capture_states": {
                state: provenance.digest(recorded.TRANSCRIPTS / f"{state}.json") for state in states
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(json.dumps(metadata))
            with mock.patch.object(source_manifest, "MANIFEST", manifest):
                self.assertEqual(
                    provenance.plan(states),
                    tuple(state for state in states if state != "ubuntu-24.04"),
                )
                metadata["capture_inputs"]["disposable/images.py"] = "0" * 64
                manifest.write_text(json.dumps(metadata))
                self.assertEqual(provenance.plan(states), states)

    def test_changed_consumer_or_provision_inputs_require_explicit_reaudit(self) -> None:
        current = provenance.inputs()
        self.assertIn("scripts/record-all-transcripts.sh", current)
        self.assertEqual(provenance.audit_digest(current), provenance.AUDITED_INPUT_DIGEST)
        for name in (
            "security/sign_in.py",
            "discovery/observations/__init__.py",
            "disposable/test_host_standing.py",
            "disposable/images.py",
            "scripts/record-all-transcripts.sh",
            "docker/disposable-server/pins.json",
        ):
            with (
                self.subTest(name=name),
                mock.patch.object(provenance, "inputs", return_value={**current, name: "edited"}),
            ):
                self.assertFalse(provenance.audited_exclusion())

    def test_unknown_resource_consumers_disable_the_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            (root / "security/sign_in.py").write_text('RESOURCE = "sign_in.sh"\n')
            with (
                mock.patch.object(source_manifest, "REPOSITORY", root),
                mock.patch.object(provenance, "inputs", return_value={}),
                mock.patch.object(provenance, "AUDITED_INPUT_DIGEST", provenance.audit_digest({})),
            ):
                self.assertTrue(provenance.audited_exclusion())
                (root / "other.py").write_text('RESOURCE = "sign_in.sh"\n')
                self.assertFalse(provenance.audited_exclusion())
                (root / "other.py").write_text('files("security.bodies").joinpath(variable)\n')
                self.assertFalse(provenance.audited_exclusion())

    def test_legacy_or_changed_pins_require_a_full_capture(self) -> None:
        states = ("ubuntu-24.04", "foundation-26.04")
        for document in (
            {},
            {"capture_inputs": {}, "capture_pins": {"ubuntu": "old"}, "capture_states": {}},
        ):
            with mock.patch.object(provenance, "_object", return_value=document):
                self.assertEqual(provenance.plan(states), states)


class CaptureReceiptTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory) / "transcripts"
        self.root.mkdir()
        self.enterContext(mock.patch.object(provenance, "PASS", self.root.parent / "pass.json"))
        self.enterContext(mock.patch.object(recorded, "TRANSCRIPTS", self.root))
        self.sources = {"read.py": "original"}
        self.enterContext(
            mock.patch.object(provenance, "inputs", side_effect=lambda: dict(self.sources))
        )
        self.enterContext(
            mock.patch.object(recorded, "current_pins", return_value={"ubuntu": "pin"})
        )

    def test_resume_refuses_changed_inputs_and_missing_prefix_receipts(self) -> None:
        self.assertEqual(
            provenance.begin(("one", "two"), resume=False, incremental=False), ("one", "two")
        )
        self.assertEqual(
            provenance.begin(("one", "two"), resume=True, incremental=False), ("one", "two")
        )
        self.sources["read.py"] = "edited"
        with self.assertRaisesMessage(ValueError, "inputs changed"):
            provenance.begin(("one", "two"), resume=True, incremental=False)

    def test_a_successful_process_without_a_written_checkpoint_is_not_a_capture(self) -> None:
        provenance.begin(("one",), resume=False, incremental=False)
        (self.root / "one.json").write_text("unchanged")
        provenance.start("one")
        with self.assertRaisesMessage(ValueError, "did not write"):
            provenance.complete("one")

    def test_finalize_cannot_refresh_a_manifest_with_missing_states(self) -> None:
        provenance.begin(("one", "two"), resume=False, incremental=False)
        (self.root / "one.json").write_text("one")
        (self.root / "two.json").write_text("two")
        with mock.patch.object(source_manifest, "write") as write:
            with self.assertRaisesMessage(ValueError, "Incomplete or stale"):
                provenance.finish()
            write.assert_not_called()

    def test_verified_unchanged_state_can_be_inherited_but_tampering_requires_capture(self) -> None:
        path = self.root / "ubuntu-24.04.json"
        path.write_text("recorded bytes")
        metadata = {
            "capture_inputs": dict(self.sources),
            "capture_pins": {"ubuntu": "pin"},
            "capture_states": {"ubuntu-24.04": provenance.digest(path)},
        }
        with mock.patch.object(provenance, "_object", return_value=metadata):
            self.assertEqual(provenance.plan(("ubuntu-24.04",)), ())
            path.write_text("tampered bytes")
            self.assertEqual(provenance.plan(("ubuntu-24.04",)), ("ubuntu-24.04",))

    def test_recorded_output_receipt_finalizes_and_tampering_invalidates_it(self) -> None:
        state = "ubuntu-24.04"
        original = source_manifest.REPOSITORY / "discovery/transcripts/ubuntu-24.04.json"
        native_bytes = original.read_bytes()
        pins = dict(recorded.parse(native_bytes.decode(), state).pins)
        manifest = self.root.parent / "manifest.json"
        with (
            mock.patch.object(recorded, "current_pins", return_value=pins),
            mock.patch.object(source_manifest, "MANIFEST", manifest),
        ):
            provenance.begin((state,), resume=False, incremental=False)
            provenance.start(state)
            (self.root / f"{state}.json").write_bytes(native_bytes)
            provenance.complete(state)
            provenance.finish()
            self.assertEqual(source_manifest.stale(), ())
            self.assertEqual(provenance.plan((state,)), ())
            (self.root / f"{state}.json").write_bytes(native_bytes + b" ")
            self.assertEqual(source_manifest.stale(), ("capture:ubuntu-24.04",))

    def test_receipt_documents_are_json_and_not_server_output(self) -> None:
        provenance.begin(("one",), resume=False, incremental=False)
        document = json.loads(provenance.PASS.read_text())
        self.assertEqual(document["inputs"], {"read.py": "original"})
        self.assertEqual(document["completed"], {})
