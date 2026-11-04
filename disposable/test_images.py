import io
import os
import tempfile
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from . import images
from .docker import DockerError
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

    def test_an_archive_without_the_keyed_tag_reports_and_rebuilds(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"BARECTL_NATIVE_L0_CACHE": directory}),
            mock.patch.object(images, "tag", return_value="barectl-disposable-l0:26.04-key"),
            mock.patch.object(images, "docker"),
            mock.patch.object(images, "exists", return_value=False),
            redirect_stderr(io.StringIO()) as error,
        ):
            (Path(directory) / "l1.tar").write_bytes(b"image")
            self.assertFalse(images.load("L1"))
        self.assertIn("does not hold", error.getvalue())

    def test_replace_overwrites_an_archive_left_by_an_older_key(self) -> None:
        saved: list[str] = []

        def docker(*arguments: str, timeout: float = 0) -> str:
            saved.append(arguments[0])
            if arguments[0] == "save":
                Path(arguments[2]).write_bytes(b"fresh")
            return ""

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"BARECTL_NATIVE_L0_CACHE": directory}),
            mock.patch.object(images, "tag", return_value="barectl-disposable-l0:26.04-key"),
            mock.patch.object(images, "docker", side_effect=docker),
            mock.patch.object(images, "exists", return_value=True),
        ):
            archive = Path(directory) / "l1.tar"
            archive.write_bytes(b"stale")
            images.store("L1")
            self.assertEqual(archive.read_bytes(), b"stale")
            images.store("L1", replace=True)
            self.assertEqual(archive.read_bytes(), b"fresh")

    def test_archive_matches_reads_the_saved_image_tag(self) -> None:
        import json
        import tarfile

        def archive(directory: Path, layers: list[dict[str, object]]) -> Path:
            path = directory / "l1.tar"
            payload = json.dumps(layers).encode()
            with tarfile.open(path, "w") as saved:
                info = tarfile.TarInfo("manifest.json")
                info.size = len(payload)
                saved.addfile(info, io.BytesIO(payload))
            return path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = archive(root, [{"RepoTags": ["barectl-disposable-l0:26.04-old"]}])
            with (
                mock.patch.dict(os.environ, {"BARECTL_NATIVE_L0_CACHE": str(root)}),
                mock.patch.object(images, "tag", return_value="barectl-disposable-l0:26.04-new"),
            ):
                self.assertFalse(images.archive_matches("L1"))
                archive(root, [{"RepoTags": ["barectl-disposable-l0:26.04-new"]}])
                self.assertTrue(images.archive_matches("L1"))
            path.unlink()
            self.assertFalse(images.archive_matches("L1"))

    def test_archived_reports_a_keyed_archive_without_loading_it(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"BARECTL_NATIVE_L0_CACHE": directory}),
            mock.patch.object(images, "tag", return_value="barectl-disposable-l0:26.04-key"),
            mock.patch.object(images, "docker") as docker,
        ):
            self.assertFalse(images.archived("L1"))
            (Path(directory) / "l1.tar").write_bytes(b"image")
            self.assertTrue(images.archived("L1"))
            docker.assert_not_called()
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(images.archived("L1"))


class PreparedSitesLayerTests(SimpleTestCase):
    def test_the_prepared_sites_layer_key_follows_the_site_body(self) -> None:
        self.assertEqual(images.prepared_sites_inputs("aaaa"), images.prepared_sites_inputs("aaaa"))
        self.assertNotEqual(
            images.prepared_sites_inputs("aaaa"), images.prepared_sites_inputs("bbbb")
        )

    def test_the_prepared_sites_cache_key_names_the_l2_layer(self) -> None:
        with mock.patch.object(images, "key", return_value="abcd1234"):
            self.assertEqual(images.cache_key("L2"), "l2-abcd1234")

    def test_an_unbuilt_l2_is_not_built_from_the_dockerfile(self) -> None:
        with (
            mock.patch.object(images, "key", return_value="abcd1234"),
            mock.patch.object(images, "load", return_value=False),
            self.assertRaises(DockerError),
        ):
            images.ensure("L2")


class PreparedCacheLayerTests(SimpleTestCase):
    def test_the_prepared_cache_layer_key_follows_the_cache_bodies(self) -> None:
        self.assertEqual(images.prepared_cache_inputs("aaaa"), images.prepared_cache_inputs("aaaa"))
        self.assertNotEqual(
            images.prepared_cache_inputs("aaaa"), images.prepared_cache_inputs("bbbb")
        )

    def test_the_prepared_cache_cache_key_names_the_l4_layer(self) -> None:
        with mock.patch.object(images, "key", return_value="abcd1234"):
            self.assertEqual(images.cache_key("L4"), "l4-abcd1234")

    def test_an_unbuilt_l4_is_not_built_from_the_dockerfile(self) -> None:
        with (
            mock.patch.object(images, "key", return_value="abcd1234"),
            mock.patch.object(images, "load", return_value=False),
            self.assertRaises(DockerError),
        ):
            images.ensure("L4")


class PreparedWordPressLayerTests(SimpleTestCase):
    def test_the_prepared_wordpress_layer_key_follows_its_bodies(self) -> None:
        self.assertEqual(
            images.prepared_wordpress_inputs("aaaa"), images.prepared_wordpress_inputs("aaaa")
        )
        self.assertNotEqual(
            images.prepared_wordpress_inputs("aaaa"), images.prepared_wordpress_inputs("bbbb")
        )

    def test_the_prepared_wordpress_cache_key_names_the_l3_layer(self) -> None:
        with mock.patch.object(images, "key", return_value="abcd1234"):
            self.assertEqual(images.cache_key("L3"), "l3-abcd1234")

    def test_a_prepared_format_bump_retires_the_prepared_layer_keys(self) -> None:
        builders = (
            images.prepared_wordpress_inputs,
            images.prepared_cache_inputs,
            images.prepared_laravel_cache_inputs,
        )
        for builder in builders:
            with self.subTest(builder=builder.__name__):
                before = builder("aaaa")
                with mock.patch.object(images, "PREPARED_FORMAT", "3"):
                    self.assertNotEqual(builder("aaaa"), before)

    def test_an_unbuilt_l3_is_not_built_from_the_dockerfile(self) -> None:
        with (
            mock.patch.object(images, "key", return_value="abcd1234"),
            mock.patch.object(images, "load", return_value=False),
            self.assertRaises(DockerError),
        ):
            images.ensure("L3")
