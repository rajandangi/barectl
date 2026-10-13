import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from . import mirror


def entry(path: str = "nar/x.nar", architecture: str = "aarch64-linux") -> mirror.Entry:
    return mirror.Entry("cache.nixos.org", path, "a" * 64, 3, architecture)


class ManifestTests(SimpleTestCase):
    def test_round_trips_through_text(self) -> None:
        manifest = mirror.Manifest((entry(), entry("nar/y.nar", "x86_64-linux")))
        self.assertEqual(mirror.Manifest.parse(manifest.dumps()), manifest)

    def test_rejects_a_document_of_another_format(self) -> None:
        with self.assertRaises(mirror.MirrorError):
            mirror.Manifest.parse(json.dumps({"format": 99, "entries": []}))

    def test_rejects_an_entry_missing_a_field(self) -> None:
        text = json.dumps({"format": 1, "entries": [{"host": "h", "path": "p"}]})
        with self.assertRaises(mirror.MirrorError):
            mirror.Manifest.parse(text)

    def test_selects_one_architecture(self) -> None:
        manifest = mirror.Manifest((entry(), entry("nar/y.nar", "x86_64-linux")))
        self.assertEqual(len(manifest.for_architecture("aarch64-linux")), 1)
        self.assertEqual(manifest.architectures(), ("aarch64-linux", "x86_64-linux"))

    def test_lists_the_hosts_it_serves(self) -> None:
        manifest = mirror.Manifest(
            (
                entry(),
                mirror.Entry("releases.nixos.org", "nix/x.tar.xz", "b" * 64, 3, "aarch64-linux"),
            )
        )
        self.assertEqual(manifest.hosts(), ("cache.nixos.org", "releases.nixos.org"))


class NarinfoTests(SimpleTestCase):
    def test_reads_fields_from_a_narinfo(self) -> None:
        data = b"StorePath: /nix/store/x\nURL: nar/x.nar.zst\nReferences: a b\n"
        fields = mirror._narinfo_fields(data)
        self.assertEqual(fields["URL"], "nar/x.nar.zst")
        self.assertEqual(fields["References"], "a b")


class ClosureTests(SimpleTestCase):
    def test_walks_a_narinfo_and_its_references(self) -> None:
        top = "a" * 32
        reference = "b" * 32
        files = {
            f"{top}.narinfo": f"URL: nar/top.nar.zst\nReferences: {reference}-ref\n".encode(),
            "nar/top.nar.zst": b"",
            f"{reference}.narinfo": b"URL: nar/ref.nar.zst\n",
            "nar/ref.nar.zst": b"",
        }
        stored: list[tuple[str, str]] = []

        def store(host: str, path: str, architecture: str, expected: str | None = None) -> bytes:
            stored.append((host, path))
            return files[path]

        mirror._walk(f"/nix/store/{top}-top", "aarch64-linux", store)
        self.assertEqual(
            stored,
            [
                ("cache.nixos.org", f"{top}.narinfo"),
                ("cache.nixos.org", "nar/top.nar.zst"),
                ("cache.nixos.org", f"{reference}.narinfo"),
                ("cache.nixos.org", "nar/ref.nar.zst"),
            ],
        )

    def test_refuses_a_store_path_of_the_wrong_shape(self) -> None:
        with self.assertRaises(mirror.MirrorError):
            mirror._walk("/nix/store/not-a-store-path", "aarch64-linux", lambda *a, **k: b"")


class FetchTests(SimpleTestCase):
    def test_verifies_the_hash_and_writes_the_file(self) -> None:
        data = b"payload"
        target = mirror.Entry("cache.nixos.org", "x.narinfo", mirror.sha256(data), len(data), "a")
        manifest = mirror.Manifest((target,))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(mirror, "download", return_value=data):
                written = mirror.fetch(manifest, root)
            self.assertEqual(written, 1)
            self.assertEqual((root / "cache.nixos.org" / "x.narinfo").read_bytes(), data)

    def test_refuses_a_hash_mismatch(self) -> None:
        target = mirror.Entry("cache.nixos.org", "x.narinfo", "f" * 64, 7, "a")
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(mirror, "download", return_value=b"payload"),
            self.assertRaises(mirror.MirrorError),
        ):
            mirror.fetch(mirror.Manifest((target,)), Path(directory))


class DriftTests(SimpleTestCase):
    def test_reports_an_entry_whose_upstream_bytes_changed(self) -> None:
        manifest = mirror.Manifest((entry("nar/x.nar"),))
        with patch.object(mirror, "download", return_value=b"different"):
            self.assertEqual(len(mirror.drift(manifest)), 1)

    def test_reports_nothing_when_upstream_matches(self) -> None:
        data = b"same"
        target = mirror.Entry("cache.nixos.org", "x", mirror.sha256(data), len(data), "a")
        with patch.object(mirror, "download", return_value=data):
            self.assertEqual(mirror.drift(mirror.Manifest((target,))), [])


class ArchitectureTests(SimpleTestCase):
    def test_maps_docker_architecture_to_the_catalog_name(self) -> None:
        with patch.dict("os.environ", {"BARECTL_MIRROR_ARCH": "arm64"}):
            self.assertEqual(mirror.host_architecture(), "aarch64-linux")
        with patch.dict("os.environ", {"BARECTL_MIRROR_ARCH": "amd64"}):
            self.assertEqual(mirror.host_architecture(), "x86_64-linux")

    def test_refuses_an_unknown_architecture(self) -> None:
        with (
            patch.dict("os.environ", {"BARECTL_MIRROR_ARCH": "mips"}),
            self.assertRaises(mirror.MirrorError),
        ):
            mirror.host_architecture()
