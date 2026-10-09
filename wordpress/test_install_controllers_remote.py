"""Independent controllers and the WordPress installation
(docs/wordpress.md#applying-an-installation).

Tagged ``ssh`` and skipped unless the disposable server is configured. Each controller is a
separate process with its own database file, SSH alias and key. Two of them review the same
prepared site and apply their reviews with the submissions released together: at most one
installs, and the other stops under the shared native lock before changing anything. A third,
fresh controller then reconstructs the installed application from the server alone, without
either controller's records.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import override

from bootstrap.models import Execution
from dashboard.testing import TEST_MANIFEST
from discovery.native_testing import setting
from operations.models import RemoteOperation

from .test_install_apply_remote import IDENTIFIER, InstallApplyTestCase
from .test_install_remote import FORM

Status = RemoteOperation.Status
FORM_FIELDS = json.dumps(FORM)

# "prepare" creates the controller's database, account and registration, discovers the server
# and reviews the installation through the site page. "apply" requests that review's run and
# runs the worker; the submission waits until every controller named in the barrier directory
# is about to submit. "fresh" only discovers the server and prints what its site page shows.
CONTROLLER = """
import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest, alias, name, barrier, phase, identifier, form = sys.argv[1:]
configured.DATABASES["default"]["NAME"] = database
configured.SSH_CONFIG_PATH = ssh_config
configured.VITE_MANIFEST_PATH = Path(manifest)
configured.VITE_DEV_SERVER_URL = ""
configured.ALLOWED_HOSTS = ["testserver"]

import django

django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client

from bootstrap.models import ApplyRun, ConfigurationPlan, PlanPreparation
from discovery import ssh
from discovery.fakes import run_worker
from discovery.services import request_discovery
from servers.models import Server

client = Client()
PERMISSIONS = (
    "view_server",
    "view_siteobservation",
    "view_wordpressplan",
    "prepare_wordpressplan",
    "install_wordpress",
    "view_siteapplicationobservation",
)

if phase == "prepare":
    call_command("migrate", verbosity=0)
    user = get_user_model().objects.create_user(f"{name}-operator")
    for codename in PERMISSIONS:
        user.user_permissions.add(Permission.objects.get(codename=codename))
    server = Server.objects.create(name=f"Disposable {name}", ssh_alias=alias)
    client.force_login(user)
    request_discovery(server)
    run_worker()
    client.post(
        f"/servers/{server.pk}/sites/{identifier}/wordpress/install/prepare/",
        json.loads(form),
        secure=True,
    )
    run_worker()
    preparation = PlanPreparation.objects.latest("pk")
    plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
    print(json.dumps({"eligible": bool(plan and plan.eligible), "status": preparation.status}))
elif phase == "apply":
    client.force_login(get_user_model().objects.get())
    real = ssh.connect

    class Synchronized:
        def __init__(self, shell):
            self.shell = shell

        @property
        def host_key(self):
            return self.shell.host_key

        def run(self, command):
            if command.startswith("sudo -n /usr/bin/systemd-run "):
                Path(barrier, name).touch()
                deadline = time.monotonic() + 120
                while {"a", "b"} - set(os.listdir(barrier)) and time.monotonic() < deadline:
                    time.sleep(0.005)
            return self.shell.run(command)

    @contextmanager
    def connect(target):
        with real(target) as shell:
            yield Synchronized(shell)

    ssh.connect = connect
    plan = ConfigurationPlan.objects.get()
    started = time.monotonic()
    client.post(f"/plans/{plan.pk}/apply/", secure=True)
    run_worker()
    run = ApplyRun.objects.get()
    print(json.dumps({
        "status": run.status,
        "execution": run.execution,
        "verification": run.verification,
        "failure": run.failure,
        "unit": run.unit_name,
        "seconds": time.monotonic() - started,
    }), flush=True)
else:
    call_command("migrate", verbosity=0)
    user = get_user_model().objects.create_user(f"{name}-operator")
    for codename in PERMISSIONS:
        user.user_permissions.add(Permission.objects.get(codename=codename))
    server = Server.objects.create(name=f"Disposable {name}", ssh_alias=alias)
    client.force_login(user)
    request_discovery(server)
    run_worker()
    page = client.get(f"/servers/{server.pk}/sites/{identifier}/wordpress/", secure=True)
    print(json.dumps({
        "status": page.status_code,
        "html": page.content.decode(),
        "runs": ApplyRun.objects.count(),
        "plans": ConfigurationPlan.objects.count(),
    }))
"""


class InstallControllerTests(InstallApplyTestCase):
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
        self.assertEqual(sorted(self.units()), sorted(str(r["unit"]) for r in results))

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
