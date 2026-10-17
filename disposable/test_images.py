import os
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from . import images
from .images import foundation_inputs


class FoundationSnapshotKeyTests(SimpleTestCase):
    def test_changing_one_payload_byte_selects_a_different_snapshot(self) -> None:
        original = b"reviewed native foundation payload\n"
        self.assertNotEqual(foundation_inputs(original), foundation_inputs(original + b" "))
        self.assertEqual(foundation_inputs(original), foundation_inputs(original))


class SnapshotArchiveTests(SimpleTestCase):
    def test_a_stored_l1_is_loaded_on_a_fresh_host_instead_of_prepared(self) -> None:
        loaded: set[str] = set()

        def docker(*arguments: str, timeout: float = 0) -> str:
            if arguments[0] == "save":
                Path(arguments[2]).write_bytes(b"image")
            if arguments[0] == "load":
                loaded.add("barectl-disposable-l0:26.04-key")
            return ""

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"BARECTL_NATIVE_L0_CACHE": directory}),
            mock.patch.object(images, "tag", return_value="barectl-disposable-l0:26.04-key"),
            mock.patch.object(images, "docker", side_effect=docker),
            mock.patch.object(images, "exists", side_effect=lambda image: image in loaded),
        ):
            self.assertFalse(images.load("L1"))
            loaded.add("barectl-disposable-l0:26.04-key")
            images.store("L1")
            self.assertTrue((Path(directory) / "l1.tar").exists())
            loaded.clear()
            self.assertTrue(images.load("L1"))
