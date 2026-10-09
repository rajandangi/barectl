import io
import shutil
import socket
import ssl
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import call, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import SimpleTestCase

from . import runner


class SelectionTests(SimpleTestCase):
    def test_one_method_dispatches_exactly_the_selected_test(self) -> None:
        method = (
            "tls.test_issuance_remote.IssuanceTests."
            "test_create_and_install_runs_all_steps_from_one_request"
        )
        with tempfile.TemporaryDirectory() as directory:
            items = runner.select([method], 1, None, Path(directory) / "durations.json")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].tests, (method,))
        self.assertEqual(items[0].labels, (method,))
        dispatched = runner.discover(items[0].labels, browser=False)
        self.assertEqual([test for tests in dispatched.values() for test in tests], [method])

    def test_a_complete_class_keeps_class_dispatch(self) -> None:
        label = "tls.test_issuance_remote.IssuanceTests"
        tests = runner.discover([label], browser=False)[label]
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(runner, "read_durations", return_value=dict.fromkeys(tests, 1.0)),
        ):
            items = runner.select([label], 1, None, Path(directory) / "durations.json")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].labels, (label,))
        self.assertEqual(items[0].tests, tuple(tests))


class PhpSourceFixtureLaneTests(SimpleTestCase):
    def test_every_lane_serves_the_php_source_fixture_as_the_publisher(self) -> None:
        lane = runner.Lane(
            "24.04",
            1,
            runner.Baseline("24.04", "image", "server", "aarch64", "", frozenset()),
            runner.Keys(Path("id"), Path("id2")),
            Path("fixtures"),
            runner.Output(io.StringIO()),
            name="lane",
            network="lane",
        )
        with patch.object(runner.Lane, "container") as container:
            lane.start_fixtures()
        aliases = [
            c.args[c.args.index("--network-alias") + 1]
            for c in container.call_args_list
            if "--network-alias" in c.args
        ]
        self.assertIn(runner.PHP_SOURCE_HOST, aliases)


class AcmeCertificateTests(SimpleTestCase):
    def test_generated_fixture_serves_with_default_strict_certificate_validation(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "fixture-root")])
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, True, False, False, False),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256())
        )
        root_pem = certificate.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        def copy_root(*arguments: str) -> str:
            if arguments[0] == "cp":
                Path(arguments[2]).write_bytes(key_pem if "key.pem" in arguments[1] else root_pem)
            return ""

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(runner, "docker", copy_root), patch.object(runner, "quietly"):
                acme = runner.acme_fixtures(Path(directory))
            client = ssl.create_default_context(cafile=str(acme / "minica.pem"))
            self.assertTrue(client.verify_flags & ssl.VERIFY_X509_STRICT)
            self.assertTrue(client.check_hostname)
            self.assertEqual(client.verify_mode, ssl.CERT_REQUIRED)
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.load_cert_chain(acme / "fixture.pem", acme / "fixture.key")
            left, right = socket.socketpair()
            left.settimeout(5)
            right.settimeout(5)

            def serve() -> None:
                with server.wrap_socket(left, server_side=True) as connection:
                    connection.sendall(b"trusted fixture")

            with left, right, ThreadPoolExecutor(1) as pool:
                result = pool.submit(serve)
                with client.wrap_socket(right, server_hostname="pebble-short") as connection:
                    self.assertEqual(connection.recv(64), b"trusted fixture")
                result.result()


class BaselineTests(SimpleTestCase):
    def test_fingerprint_changes_with_release_and_fixture_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            for source in runner.FIXTURE.iterdir():
                if source.is_file():
                    shutil.copy(source, fixture)
            with patch.object(runner, "FIXTURE", fixture):
                original = runner.fingerprint("24.04")
                self.assertNotEqual(original, runner.fingerprint("26.04"))
                with (fixture / "provision.sh").open("a") as handle:
                    handle.write("\ntrue\n")
                changed = runner.fingerprint("24.04")
                self.assertNotEqual(original, changed)
                with patch("bootstrap.php_supply.KEY_SHA256", "0" * 64):
                    self.assertNotEqual(changed, runner.fingerprint("24.04"))

    def test_cache_key_expires_at_the_next_twelve_hour_period(self) -> None:
        keys: list[str] = []
        for timestamp in (runner.BASELINE_MAX_AGE - 1, runner.BASELINE_MAX_AGE):
            output = io.StringIO()
            with (
                patch("sys.stdout", output),
                patch("disposable.runner.time.time", return_value=timestamp),
            ):
                self.assertEqual(runner.main(["--release", "24.04", "--baseline-cache-key"]), 0)
            keys.append(output.getvalue().strip())
        self.assertEqual(keys[0].rsplit("-", 1)[0], keys[1].rsplit("-", 1)[0])
        self.assertNotEqual(keys[0], keys[1])

    def test_restored_archives_are_reused_only_while_fresh(self) -> None:
        for age in (60, runner.BASELINE_MAX_AGE + 1, None):
            with self.subTest(age=age), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "24.04.tar"
                archive.touch()
                with (
                    patch.dict(
                        "os.environ",
                        {"BARECTL_NATIVE_BASELINE_CACHE": directory, "BARECTL_NATIVE_REBUILD": "0"},
                    ),
                    patch.object(runner, "cache_directory", return_value=Path(directory)),
                    patch.object(runner, "image_age", side_effect=[None, age]),
                    patch.object(runner, "build_baseline") as build,
                    patch.object(runner, "docker", return_value="ssh.service") as docker,
                    patch.object(runner.Server, "boot") as boot,
                ):
                    boot.return_value.exec.side_effect = ["x86_64", "native revisions"]
                    baseline = runner.baseline("24.04", runner.Output(io.StringIO()))
                    docker.assert_any_call("load", "--input", str(archive), timeout=600)
                    boot.return_value.remove.assert_called_once()
                    if age is None or age > runner.BASELINE_MAX_AGE:
                        build.assert_called_once_with("24.04", baseline.server, baseline.image)
                        docker.assert_has_calls(
                            [
                                call(
                                    "save",
                                    "--output",
                                    str(archive),
                                    baseline.image,
                                    baseline.server,
                                    timeout=600,
                                )
                            ]
                        )
                    else:
                        build.assert_not_called()
                    self.assertEqual(baseline.services, frozenset({"ssh.service"}))

    def test_controller_keys_are_new_for_each_run(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            keys = runner.controller_keys(Path(first))
            other = runner.controller_keys(Path(second))
            self.assertNotEqual(keys.authorized(), other.authorized())
            self.assertNotEqual(keys.first.read_bytes(), keys.second.read_bytes())
