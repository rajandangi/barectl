import io
import shutil
import tempfile
from pathlib import Path
from unittest.mock import call, patch

from django.test import SimpleTestCase

from . import runner


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
                self.assertNotEqual(original, runner.fingerprint("24.04"))

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
