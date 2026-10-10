"""Independent WordPress controllers (docs/wordpress.md#applying-an-installation)."""

import json
import subprocess
import sys
from pathlib import Path
from typing import override

from bootstrap.models import Execution
from dashboard.testing import TEST_MANIFEST
from discovery.native_testing import setting
from operations.models import RemoteOperation

from .controllers_remote_testing import CONTROLLER
from .install_apply_remote_testing import InstallApplyTestCase
from .install_remote_testing import FORM, IDENTIFIER

Status = RemoteOperation.Status
FORM_FIELDS = json.dumps(FORM)


class InstallControllerCase(InstallApplyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.barrier = self.directory / "barrier"
        self.barrier.mkdir()

    def controller(
        self, name: str, alias: str, phase: str, *, config: Path | None = None
    ) -> subprocess.Popen[str]:
        directory = self.directory / name
        directory.mkdir(exist_ok=True)
        arguments = [
            str(directory / "db.sqlite3"),
            str(config or self.config),
            str(TEST_MANIFEST),
            alias,
            name,
            str(self.barrier),
            phase,
            IDENTIFIER,
            FORM_FIELDS,
        ]
        return subprocess.Popen(  # noqa: S603 - the test's own script
            [sys.executable, "-c", CONTROLLER, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def finish(self, process: subprocess.Popen[str]) -> dict[str, object]:
        stdout, stderr = process.communicate(timeout=600)
        self.assertEqual(process.returncode, 0, stderr[-3000:])
        result: dict[str, object] = json.loads(stdout.strip().splitlines()[-1])
        return result

    def test_two_controllers_applying_together_install_at_most_once(self) -> None:
        earlier = self.units()
        controllers = {"a": "disposable", "b": "disposable-second"}
        for name, alias in controllers.items():
            prepared = self.finish(self.controller(name, alias, "prepare"))
            self.assertTrue(prepared["eligible"], prepared)
        racing = [self.controller(name, alias, "apply") for name, alias in controllers.items()]
        results = [self.finish(process) for process in racing]
        executions = [str(result["execution"]) for result in results]
        succeeded = [r for r in results if r["execution"] == Execution.SUCCEEDED]
        refused = [r for r in results if r["execution"] != Execution.SUCCEEDED]
        # At most one installation ran. Every other run stopped under the lock before
        # changing anything; a run that started after the winner finished found changed
        # evidence instead. Simultaneous submissions may both refuse.
        self.assertLessEqual(len(succeeded), 1, executions)
        self.assertTrue(refused, executions)
        for run in refused:
            self.assertIn(
                run["execution"],
                {Execution.LOCK_CONFLICT, Execution.OTHER_RUN_ACTIVE, Execution.DRIFT},
                executions,
            )
            self.assertEqual(run["status"], Status.FAILED)
            self.assertIn("Prepare a new review", str(run["failure"]))
            self.assertNotIn("barectl-wordpress: gate verified", self.journal(str(run["unit"])))
        for run in succeeded:
            self.assertEqual(run["status"], Status.SUCCEEDED, run["failure"])
            self.assertEqual(run["verification"], "passed")
        self.assertEqual(self.tables(), "12" if succeeded else "0")
        self.assertEqual(
            self.administer(f"ls -A /var/www/{IDENTIFIER}").split(), ["private", "public"]
        )
        self.assertEqual(
            sorted(self.units()), sorted([*earlier, *(str(r["unit"]) for r in results)])
        )

    def test_a_fresh_controller_reconstructs_the_application_from_the_server(self) -> None:
        run = self.apply_install(self.eligible())
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        # A root-authorized controller with its own key and an empty database.
        config = self.directory / "fresh-config"
        config.write_text(
            f"Host disposable-root\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User root\n  IdentityFile {setting('SECOND_KEY')}\n"
            f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n",
            encoding="utf-8",
        )
        fresh = self.finish(self.controller("fresh", "disposable-root", "fresh", config=config))
        self.assertEqual(fresh["status"], 200)
        html = str(fresh["html"])
        card = html[html.index("site-application-heading") :][:3000]
        self.assertIn("Installed", card, card)
        self.assertIn("7.1.3", card, card)
        # Nothing of the first controller's records exists in the second's database.
        self.assertEqual((fresh["runs"], fresh["plans"]), (0, 0))
