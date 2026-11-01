import io
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from email.message import Message
from pathlib import Path
from unittest.mock import patch

import yaml
from django.test import SimpleTestCase

from . import images, mirror


def entry(path: str = "nar/x.nar", architecture: str = "aarch64-linux") -> mirror.Entry:
    return mirror.Entry("cache.nixos.org", path, "a" * 64, 3, architecture)


class DownloadTests(SimpleTestCase):
    def test_a_transient_5xx_is_retried_before_the_entry_fails(self) -> None:
        with (
            patch("disposable.mirror.time.sleep") as sleep,
            patch("disposable.mirror.urllib.request.urlopen") as urlopen,
        ):
            response = urlopen.return_value.__enter__.return_value
            response.read.return_value = b"payload"
            response.__enter__.return_value = response
            error = urllib.error.HTTPError(
                "https://example.test/x", 503, "unavailable", Message(), None
            )
            urlopen.side_effect = [error, response]
            self.assertEqual(mirror.download("https://example.test/x"), b"payload")
            self.assertEqual(urlopen.call_count, 2)
            sleep.assert_called_once()


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

    def test_a_source_path_is_the_upstream_url_and_survives_the_manifest(self) -> None:
        target = mirror.Entry(
            "api.wordpress.org",
            "core/checksums/1.0/index.html",
            "a" * 64,
            3,
            "aarch64-linux",
            source="core/checksums/1.0/?version=7.1.3&locale=en_US",
        )
        self.assertEqual(
            target.url,
            "https://api.wordpress.org/core/checksums/1.0/?version=7.1.3&locale=en_US",
        )
        self.assertEqual(
            mirror.Manifest.parse(mirror.Manifest((target,)).dumps()).entries[0], target
        )

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

        def store(
            host: str,
            path: str,
            architecture: str,
            expected: str | None = None,
            *,
            source: str | None = None,
        ) -> bytes:
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


def collector() -> tuple[list[tuple[str, str]], mirror._StoreFn]:
    stored: list[tuple[str, str]] = []

    def store(
        host: str,
        path: str,
        architecture: str,
        expected: str | None = None,
        *,
        source: str | None = None,
    ) -> bytes:
        stored.append((host, path))
        return b""

    return stored, store


class FixtureTests(SimpleTestCase):
    def test_the_updates_fixture_has_a_release_pocket_and_security_copy(self) -> None:
        paths = {
            entry.path
            for entry in mirror.Manifest.parse(mirror.MANIFEST.read_text()).entries
            if entry.host == mirror.SNAPSHOT_HOST and "/pool/main/o/openssl/" in entry.path
        }
        self.assertIn(
            f"{mirror.SNAPSHOT_ROOT}/pool/main/o/openssl/openssl_3.5.5-1ubuntu3_amd64.deb",
            paths,
        )
        self.assertIn(
            f"{mirror.SNAPSHOT_ROOT}/pool/main/o/openssl/openssl_3.5.5-1ubuntu3.7_amd64.deb",
            paths,
        )

    def test_apt_sources_name_the_mirrored_snapshot(self) -> None:
        text = mirror.apt_sources()
        self.assertIn(f"https://{mirror.SNAPSHOT_HOST}/{mirror.SNAPSHOT_ROOT}", text)
        self.assertIn("resolute resolute-updates resolute-security", text)
        self.assertIn("Components: main", text)

    def test_snapshot_entries_mirror_indices_and_the_resolved_packages(self) -> None:
        stored, store = collector()
        deb = f"https://{mirror.SNAPSHOT_HOST}/{mirror.SNAPSHOT_ROOT}/pool/main/m/mariadb/x.deb"
        with (
            patch.object(mirror, "_package_urls", return_value=[deb]),
            patch.object(mirror, "_release_pocket_urls", return_value=[]),
            patch.object(mirror, "_security_pocket_urls", return_value=[]),
        ):
            mirror._snapshot_entries("x86_64-linux", store)
        paths = {path for _, path in stored}
        root = mirror.SNAPSHOT_ROOT
        self.assertIn(f"{root}/dists/resolute/InRelease", paths)
        self.assertIn(f"{root}/dists/resolute/main/binary-amd64/Packages.xz", paths)
        self.assertIn(f"{root}/dists/resolute-security/main/cnf/Commands-amd64.xz", paths)
        self.assertIn(f"{root}/pool/main/m/mariadb/x.deb", paths)

    def test_pebble_entries_mirror_the_binary_and_the_certificates(self) -> None:
        stored, store = collector()
        mirror._pebble_entries("aarch64-linux", store)
        paths = {path for _, path in stored}
        self.assertIn(
            "letsencrypt/pebble/releases/download/v2.10.1/pebble-linux-arm64.tar.gz", paths
        )
        self.assertIn("letsencrypt/pebble/v2.10.1/test/certs/pebble.minica.pem", paths)
        self.assertNotIn(
            "letsencrypt/pebble/releases/download/v2.10.1/pebble-linux-amd64.tar.gz", paths
        )

    def test_composer_entries_walk_the_fixture_lock(self) -> None:
        stored, store = collector()
        mirror._composer_entries("x86_64-linux", store)
        self.assertTrue(stored)
        self.assertEqual({host for host, _ in stored}, {"api.github.com"})
        self.assertTrue(all("/zipball/" in path for _, path in stored))

    def test_the_fixture_packages_are_the_engines_git_valkey_and_logrotate(self) -> None:
        self.assertEqual(
            mirror.UBUNTU_FIXTURES,
            ("mariadb-server", "postgresql", "git", "valkey-server", "logrotate"),
        )

    def test_pebble_files_are_required_from_the_mirror(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"XDG_CACHE_HOME": directory}),
            self.assertRaises(mirror.MirrorError),
        ):
            mirror.pebble_files("x86_64-linux")


class FixtureCAIdentityTests(SimpleTestCase):
    def test_fixture_cli_creates_and_reuses_ca_without_a_mirror_download(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"XDG_CACHE_HOME": directory}),
            patch.object(mirror, "load", side_effect=AssertionError("not a mirror fetch")),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(mirror.main(["fixture-ca"]), 0)
            certificate, key = mirror.fixture_ca()
            original = certificate.read_bytes(), key.read_bytes()
            self.assertTrue(original[0].startswith(b"-----BEGIN CERTIFICATE-----"))
            self.assertEqual(mirror.main(["fixture-ca"]), 0)
            self.assertEqual((certificate.read_bytes(), key.read_bytes()), original)
            key.unlink()
            self.assertEqual(mirror.main(["fixture-ca"]), 0)
            self.assertNotEqual((certificate.read_bytes(), key.read_bytes()), original)

    def test_shared_cold_ca_overwrites_stale_mirror_identity_before_shard_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {"XDG_CACHE_HOME": str(root / "producer")}):
                source_certificate, source_key = mirror.fixture_ca()
                expected = images.key()
                shared = root / "shared"
                shutil.copytree(source_certificate.parent, shared)
            observed = []
            for shard in ("shard-a", "shard-b"):
                with patch.dict(os.environ, {"XDG_CACHE_HOME": str(root / shard)}):
                    stale_certificate, _ = mirror.fixture_ca()
                    self.assertNotEqual(
                        stale_certificate.read_bytes(), source_certificate.read_bytes()
                    )
                    self.assertNotEqual(images.key(), expected)
                    shutil.copytree(shared, stale_certificate.parent, dirs_exist_ok=True)
                    certificate, key = mirror.fixture_ca()
                    self.assertEqual(key.read_bytes(), source_key.read_bytes())
                    observed.append(images.key())
                    self.assertEqual(certificate.read_bytes(), source_certificate.read_bytes())
            self.assertEqual(observed, [expected, expected])

    def test_fixture_ca_cache_policy_is_versioned_and_separate_from_manifest_cache(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(mirror.main(["fixture-ca-key"]), 0)
        self.assertEqual(
            output.getvalue().strip(), "native-fixture-ca-v1-ec-prime256v1-x509-ca-3650"
        )


class FixtureCAWorkflowTests(SimpleTestCase):
    def test_every_matrix_shard_gets_the_producers_ca_before_computing_image_keys(self) -> None:
        path = mirror.REPOSITORY / ".github/workflows/native-scenarios.yml"
        workflow = yaml.safe_load(path.read_text())
        producer = workflow["jobs"]["fixture-ca"]
        consumer = workflow["jobs"]["scenarios"]
        self.assertEqual(consumer["needs"], "fixture-ca")
        shared = next(
            step
            for step in producer["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact@")
        )
        steps = consumer["steps"]
        downloaded = next(
            step for step in steps if step.get("uses", "").startswith("actions/download-artifact@")
        )
        mirror_restore = next(step for step in steps if step.get("id") == "mirror")
        keys = next(step for step in steps if step.get("id") == "keys")
        self.assertEqual(shared["with"]["name"], downloaded["with"]["name"])
        self.assertEqual(shared["with"]["path"], downloaded["with"]["path"])
        self.assertLess(steps.index(mirror_restore), steps.index(downloaded))
        self.assertLess(steps.index(downloaded), steps.index(keys))
        ensure = next(
            step
            for step in producer["steps"]
            if "disposable.mirror fixture-ca\n" in step.get("run", "")
            or step.get("run", "").endswith("disposable.mirror fixture-ca")
        )
        self.assertLess(producer["steps"].index(ensure), producer["steps"].index(shared))
        self.assertNotIn("if", ensure)
        self.assertEqual(producer["steps"][0]["id"], "phase")
        self.assertIn("phase-started", consumer["env"]["BARECTL_NATIVE_PHASE_STARTED"])
        self.assertIn("ca-seconds", consumer["env"]["BARECTL_NATIVE_CA_SECONDS"])
        self.assertEqual(ensure["id"], "ca-preparation")

    def test_default_branch_seeding_and_mirror_restore_share_the_same_ca_policy(self) -> None:
        directory = mirror.REPOSITORY / ".github/workflows"
        native = yaml.safe_load((directory / "native.yml").read_text())
        # PyYAML's YAML1.1 loader treats the Actions `on` key as boolean true.
        self.assertEqual(native[True]["push"]["branches"], ["main"])
        scenarios = yaml.safe_load((directory / "native-scenarios.yml").read_text())
        scheduled = yaml.safe_load((directory / "native-mirror.yml").read_text())
        for job in (scenarios["jobs"]["fixture-ca"], scheduled["jobs"]["mirror"]):
            steps = job["steps"]
            key = next(step for step in steps if step.get("id") == "ca-key")
            self.assertIn("disposable.mirror fixture-ca-key", key["run"])
            restore = next(step for step in steps if step.get("id") == "ca")
            self.assertEqual(restore["with"]["key"], "${{ steps.ca-key.outputs.key }}")
            self.assertNotIn("restore-keys", restore["with"])
            ensure = next(
                step
                for step in steps
                if "disposable.mirror fixture-ca\n" in step.get("run", "")
                or step.get("run", "").endswith("disposable.mirror fixture-ca")
            )
            self.assertLess(steps.index(restore), steps.index(ensure))
        steps = scheduled["jobs"]["mirror"]["steps"]
        mirror_restore = next(step for step in steps if step.get("id") == "mirror")
        ca_restore = next(step for step in steps if step.get("id") == "ca")
        self.assertLess(steps.index(mirror_restore), steps.index(ca_restore))


class SpecialSnapshotCacheTests(SimpleTestCase):
    def test_special_layers_discard_legacy_copies_and_cache_independently(
        self,
    ) -> None:
        workflow = yaml.safe_load(
            (mirror.REPOSITORY / ".github/workflows/native-scenarios.yml").read_text()
        )
        steps = workflow["jobs"]["scenarios"]["steps"]
        keys = next(step for step in steps if step.get("id") == "keys")
        l0 = next(step for step in steps if step.get("id") == "l0")
        discard = next(step for step in steps if step.get("name", "").startswith("Discard special"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("standing-26.04.tar", "l0-24.04.tar", "l0.tar", "l1.tar", "fixture.tar"):
                (root / name).write_text("legacy")
            subprocess.run(  # noqa: S603 - actual workflow shell, isolated cache directory
                ["/bin/bash", "-e", "-c", discard["run"]],
                check=True,
                env={**os.environ, "BARECTL_NATIVE_L0_CACHE": directory},
            )
            self.assertEqual(
                sorted(path.name for path in root.iterdir()), ["fixture.tar", "l0.tar", "l1.tar"]
            )
        self.assertLess(steps.index(l0), steps.index(discard))
        for identifier, layer, archive in (
            ("standing", "L0-standing", "standing-26.04.tar"),
            ("ubuntu24", "L0-24.04", "l0-24.04.tar"),
        ):
            with self.subTest(layer=layer):
                self.assertIn(f"cache-key --layer {layer}", keys["run"])
                restore = next(step for step in steps if step.get("id") == identifier)
                self.assertLess(steps.index(discard), steps.index(restore))
                self.assertEqual(restore["uses"], "actions/cache/restore@v6.1.0")
                self.assertEqual(
                    restore["with"]["path"], "${{ env.BARECTL_NATIVE_L0_CACHE }}/" + archive
                )
                self.assertIn("steps.keys.outputs." + identifier, restore["with"]["key"])
                self.assertNotIn("restore-keys", restore["with"])
                gate = next(step for step in steps if step.get("id") == f"{identifier}-archive")
                self.assertEqual(
                    gate["if"], f"always() && steps.{identifier}.outputs.cache-hit != 'true'"
                )
                save = next(
                    step for step in steps if step.get("name") == f"Save the {layer} snapshot"
                )
                self.assertEqual(save["uses"], "actions/cache/save@v6.1.0")
                self.assertEqual(save["with"]["path"], restore["with"]["path"])
                self.assertEqual(
                    save["with"]["key"], "${{ steps." + identifier + ".outputs.cache-primary-key }}"
                )
                self.assertEqual(
                    save["if"], f"always() && steps.{identifier}-archive.outputs.present == 'true'"
                )
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    output = root / "output"
                    (root / (archive + ".partial")).write_text("incomplete")
                    for present in (False, True):
                        if present:
                            (root / archive).write_text("complete")
                        output.write_text("")
                        subprocess.run(  # noqa: S603 - actual workflow archive gate, controlled files
                            ["/bin/bash", "-e", "-c", gate["run"]],
                            check=True,
                            env={
                                **os.environ,
                                "BARECTL_NATIVE_L0_CACHE": directory,
                                "GITHUB_OUTPUT": str(output),
                            },
                        )
                        self.assertEqual(output.read_text(), "present=true\n" if present else "")


class MirrorLeafCoherenceTests(SimpleTestCase):
    def test_rotating_the_fixture_ca_cannot_reuse_a_leaf_from_the_old_mirror_cache(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"XDG_CACHE_HOME": directory}),
        ):
            old_certificate, _ = mirror.mirror_certificate(["cache.nixos.org", "git"])
            ca_certificate, ca_key = mirror.fixture_ca()
            ca_key.unlink()
            mirror.fixture_ca()
            certificate, key = mirror.mirror_certificate(["git", "cache.nixos.org"])
            self.assertNotEqual(certificate, old_certificate)
            with self.assertRaises(mirror.MirrorError):
                mirror._openssl("verify", "-CAfile", str(ca_certificate), str(old_certificate))
            mirror._openssl(
                "verify",
                "-CAfile",
                str(ca_certificate),
                "-verify_hostname",
                "cache.nixos.org",
                str(certificate),
            )
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(certificate, key)
            self.assertEqual(
                mirror.mirror_certificate(["cache.nixos.org", "git"]), (certificate, key)
            )

    def test_concurrent_first_use_returns_a_loadable_pair_to_every_lane(self) -> None:
        barrier = threading.Barrier(8)

        def first_use(index: int) -> tuple[Path, Path]:
            barrier.wait(timeout=5)
            certificate, key = mirror.mirror_certificate(["cache.nixos.org", "git"])
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(certificate, key)
            return certificate, key

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"XDG_CACHE_HOME": directory}),
        ):
            ca_certificate, _ = mirror.fixture_ca()
            with ThreadPoolExecutor(8) as pool:
                results = list(pool.map(first_use, range(8)))
            self.assertTrue(all(result == results[0] for result in results))
            mirror._openssl("verify", "-CAfile", str(ca_certificate), str(results[0][0]))

    def test_failed_leaf_signing_does_not_publish_an_incomplete_pair(self) -> None:
        original = mirror._openssl

        def refuse_signing(*arguments: str, stdin: str | None = None) -> None:
            if arguments[0] == "x509":
                raise mirror.MirrorError("test signing failure")
            original(*arguments, stdin=stdin)

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"XDG_CACHE_HOME": directory}),
        ):
            mirror.fixture_ca()
            with (
                patch.object(mirror, "_openssl", side_effect=refuse_signing),
                self.assertRaisesMessage(mirror.MirrorError, "test signing failure"),
            ):
                mirror.mirror_certificate(["cache.nixos.org"])
            certificate, key = mirror.mirror_certificate(["cache.nixos.org"])
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(certificate, key)


class NativePhaseBudgetTests(SimpleTestCase):
    def run_phase(
        self,
        elapsed: int,
        ca: str | None = "0",
        result: int = 0,
        shard: str = "2",
        runner_source: str = "",
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        workflow = yaml.safe_load(
            (mirror.REPOSITORY / ".github/workflows/native-scenarios.yml").read_text()
        )
        command = next(
            step["run"]
            for step in workflow["jobs"]["scenarios"]["steps"]
            if "finish_budget()" in step.get("run", "")
        )
        command = command.replace("${{ matrix.shard }}", shard)
        self.assertNotIn("${{", command)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            clock = root / "clock"
            clock.write_text("1000\n")
            calls = root / "calls"
            date = binary / "date"
            date.write_text('#!/bin/sh\ncat "$TEST_CLOCK"\n')
            date.chmod(0o700)
            runner = root / "docker/disposable-server/run-scenarios.sh"
            runner.parent.mkdir(parents=True)
            runner.write_text(
                runner_source
                or (
                    "#!/bin/sh\n"
                    'printf "%s\\n" "$*" >> "$TEST_CALLS"\n'
                    'now=$(cat "$TEST_CLOCK")\n'
                    'echo $((now + TEST_ELAPSED)) > "$TEST_CLOCK"\n'
                    'exit "$TEST_RESULT"\n'
                )
            )
            runner.chmod(0o700)
            environment = {
                **os.environ,
                "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                "RUNNER_TEMP": str(root),
                "BARECTL_NATIVE_CA_SECONDS": ca or "",
                "TEST_CLOCK": str(clock),
                "TEST_CALLS": str(calls),
                "TEST_ELAPSED": str(elapsed),
                "TEST_RESULT": str(result),
            }
            if ca is None:
                environment.pop("BARECTL_NATIVE_CA_SECONDS")
            completed = subprocess.run(  # noqa: S603 - actual workflow shell, controlled stubs
                ["/bin/bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", command],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            return completed, calls.read_text().splitlines() if calls.exists() else []

    def test_target_boundary(self) -> None:
        for seconds, expected in ((299, 0), (300, 0), (301, 1)):
            with self.subTest(seconds=seconds):
                result, calls = self.run_phase(seconds)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertIn(f"Complete native phase: {seconds}s", result.stdout)
                self.assertEqual(len(calls), 1)

    def test_shared_ca_duration_counts_against_target_and_hard_deadline(self) -> None:
        for seconds, expected in ((279, 0), (280, 0), (281, 1)):
            with self.subTest(seconds=seconds):
                result, calls = self.run_phase(seconds, ca="20")
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertIn("--time-limit 880", calls[0])
                self.assertIn(f"Complete native phase: {seconds + 20}s", result.stdout)

    def test_shard_one_counts_all_three_required_stages(self) -> None:
        result, calls = self.run_phase(100, shard="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assertIn("--validators --time-limit 900", calls[0])
        self.assertIn("--check-egress --time-limit 800", calls[1])
        self.assertIn("--shard 1/11 --time-limit 700", calls[2])
        self.assertIn("Complete native phase: 300s", result.stdout)

    def test_command_failure_is_preserved_even_when_target_missed(self) -> None:
        for seconds in (1, 301):
            with self.subTest(seconds=seconds):
                result, _ = self.run_phase(seconds, result=7)
                self.assertEqual(result.returncode, 7, result.stderr)

    def test_invalid_shared_duration_fails_before_any_required_command(self) -> None:
        for value in (None, "", "-1", "1.5", "unknown", "901", "9999999999999999999999999999"):
            with self.subTest(value=value):
                result, calls = self.run_phase(0, ca=value)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(calls, [])

    def test_exhausted_shared_duration_stops_before_native_commands(self) -> None:
        result, calls = self.run_phase(0, ca="900")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(calls, [])
        self.assertIn("hard limit exhausted", result.stderr)

    def test_zero_padded_shared_seconds_are_decimal(self) -> None:
        result, calls = self.run_phase(0, ca="00020")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--time-limit 880", calls[0])
        self.assertIn("Complete native phase: 20s", result.stdout)

    def test_outer_deadline_interrupts_the_native_child_and_stops_later_stages(self) -> None:
        source = (
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$TEST_CALLS"\n'
            "trap 'wait \"$child\" 2>/dev/null || true; echo child-stopped; exit 143' TERM\n"
            "sleep 30 &\n"
            "child=$!\n"
            'echo "child-pid=$child"\n'
            'wait "$child"\n'
        )
        result, calls = self.run_phase(0, ca="899", shard="1", runner_source=source)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertIn("--validators --time-limit 1", calls[0])
        self.assertIn("child-stopped", result.stdout)
        child = int(
            next(
                line for line in result.stdout.splitlines() if line.startswith("child-pid=")
            ).split("=")[1]
        )
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)
