"""Independent controllers and the Finish of a partial WordPress installation
(docs/wordpress.md#finishing-a-partial-installation).

Tagged ``ssh`` and skipped unless the disposable server is configured. Each controller is a
separate process with its own database file, SSH alias and key. The first controller (this
test's own) installs through the dashboard and is stopped after a named fragment of the body.
A second, fresh controller with an empty database, a different key and no copy of anything the
first recorded then reviews and finishes the site from the server's evidence alone. Two
controllers that review the same stranded site and apply together finish it at most once.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import override

from bootstrap.models import ApplyRun, Execution
from dashboard.testing import TEST_MANIFEST
from discovery.native_testing import setting
from operations.models import RemoteOperation

from .finish_remote_testing import FINISH_FORM
from .test_finish_remote import FinishCase
from .test_install_controllers_remote import CONTROLLER
from .test_install_remote import IDENTIFIER

Status = RemoteOperation.Status
FORM_FIELDS = json.dumps(FINISH_FORM)
# The same controller process as the installation's, asked to review a Finish instead.
FINISH_CONTROLLER = CONTROLLER.replace("wordpress/install/prepare/", "wordpress/finish/prepare/")


class FinishControllerTests(FinishCase):
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
            [sys.executable, "-c", FINISH_CONTROLLER, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def result(self, process: subprocess.Popen[str]) -> dict[str, object]:
        stdout, stderr = process.communicate(timeout=600)
        self.assertEqual(process.returncode, 0, stderr[-3000:])
        result: dict[str, object] = json.loads(stdout.strip().splitlines()[-1])
        return result

    def root_config(self) -> Path:
        """A root-authorized alias with its own key, as another device would have."""
        config = self.directory / "fresh-config"
        config.write_text(
            f"Host disposable-root\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User root\n  IdentityFile {setting('SECOND_KEY')}\n"
            f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n",
            encoding="utf-8",
        )
        return config

    def test_a_fresh_controller_finishes_what_another_controller_started(self) -> None:
        interrupted = self.interrupted("configuration")
        before = self.deep()
        config = self.root_config()
        prepared = self.result(
            self.controller("fresh", "disposable-root", "prepare", config=config)
        )
        self.assertTrue(prepared["eligible"], prepared)
        # Nothing of the first controller's records exists in the fresh controller's database,
        # and its review is of the server as it is, not of the first run.
        for name in ("a", "b"):
            (self.barrier / name).touch()
        applied = self.result(self.controller("fresh", "disposable-root", "apply", config=config))
        self.assertEqual(applied["status"], Status.SUCCEEDED, applied["failure"])
        self.assertEqual(applied["execution"], Execution.SUCCEEDED)
        self.assertEqual(applied["verification"], "passed")
        self.assertEqual(self.tables(), "12")
        self.assertEqual(
            self.administer(f"ls -A /var/www/{IDENTIFIER}").split(), ["private", "public"]
        )
        self.assertEqual(self.curl("/"), "200")
        self.assertEqual(self.curl("/wp-login.php"), "200")
        # The salts that existed before were kept; the first controller's records are untouched
        # and know nothing of the Finish.
        self.assertEqual(self.deep()["private"], before["private"])
        self.assertEqual(ApplyRun.objects.count(), 1)
        self.assertEqual(ApplyRun.objects.get().unit_name, interrupted.unit_name)
        self.assertEqual(len(self.units()), 2)

    def test_a_fresh_controller_refuses_what_it_can_not_verify(self) -> None:
        self.interrupted("publish")
        self.administer(f"printf x >/var/www/{IDENTIFIER}/public/robots.txt")
        config = self.root_config()
        prepared = self.result(
            self.controller("fresh", "disposable-root", "prepare", config=config)
        )
        self.assertFalse(prepared["eligible"], prepared)
        self.assertEqual(len(self.units()), 1, "the refused review submitted nothing")

    def test_two_controllers_applying_together_finish_at_most_once(self) -> None:
        self.interrupted("publish")
        controllers = {"a": "disposable", "b": "disposable-second"}
        for name, alias in controllers.items():
            prepared = self.result(self.controller(name, alias, "prepare"))
            self.assertTrue(prepared["eligible"], prepared)
        racing = [self.controller(name, alias, "apply") for name, alias in controllers.items()]
        results = [self.result(process) for process in racing]
        executions = [str(result["execution"]) for result in results]
        succeeded = [r for r in results if r["execution"] == Execution.SUCCEEDED]
        refused = [r for r in results if r["execution"] != Execution.SUCCEEDED]
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
        self.assertEqual(len(self.units()), 1 + len(results))
