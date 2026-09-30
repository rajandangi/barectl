"""Independent controllers creating the same site on one disposable server (docs/sites.md).

Each controller is a separate process with its own database, account, SSH alias and key; see
``bootstrap/test_coordination_remote.py`` for the pattern.
"""

import json
import subprocess
import sys
import time
from typing import override

from bootstrap.models import Execution
from dashboard.testing import TEST_MANIFEST
from operations.models import RemoteOperation

from .test_apply_remote import SiteApplyTestCase

Status = RemoteOperation.Status

# "prepare" creates the controller's database, account and registration and reviews the
# site plan; "apply" requests its run and runs the worker, whose submission waits until
# both controllers are about to submit; "review" reviews the same site again.
CONTROLLER = """
import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest, alias, name, barrier, phase, action = sys.argv[1:]
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

from bootstrap.models import ApplyRun, ConfigurationPlan
from discovery import ssh
from discovery.fakes import run_worker
from servers.models import Server

client = Client()


def prepare():
    server = Server.objects.get()
    if action == "site":
        client.post(
            f"/servers/{server.pk}/sites/prepare/",
            {"identifier": "shop", "names": "shop.test www.shop.test"},
            secure=True,
        )
    else:
        client.post(f"/servers/{server.pk}/plans/prepare/", {"action": action}, secure=True)
    run_worker()
    return ConfigurationPlan.objects.latest("pk")


if phase == "prepare":
    call_command("migrate", verbosity=0)
    user = get_user_model().objects.create_user(f"{name}-operator")
    for codename in (
        "view_server",
        "view_siteplan",
        "prepare_siteplan",
        "apply_siteplan",
        "view_configurationplan",
        "prepare_configurationplan",
        "apply_configurationplan",
    ):
        user.user_permissions.add(Permission.objects.get(codename=codename))
    Server.objects.create(name=f"Disposable {name}", ssh_alias=alias)
    client.force_login(user)
    plan = prepare()
    print(json.dumps({"plan": plan.pk, "eligible": plan.eligible}), flush=True)
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
    client.post(f"/plans/{plan.pk}/apply/", secure=True)
    run_worker()
    run = ApplyRun.objects.get(plan_number=plan.pk)
    print(json.dumps({
        "status": run.status,
        "execution": run.execution,
        "exit_status": run.exit_status,
        "failure": run.failure,
        "unit": run.unit_name,
    }), flush=True)
else:
    client.force_login(get_user_model().objects.get())
    plan = prepare()
    print(json.dumps({
        "eligible": plan.eligible,
        "no_changes": plan.no_changes,
        "refusals": list(plan.refusals.values_list("text", flat=True)),
    }), flush=True)
"""


class SiteCoordinationTests(SiteApplyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        (self.directory / "barrier").mkdir()

    def controller(
        self, name: str, alias: str, phase: str, action: str = "site"
    ) -> subprocess.Popen[str]:
        directory = self.directory / name
        directory.mkdir(exist_ok=True)
        arguments = [
            str(directory / "db.sqlite3"),
            str(self.config),
            str(TEST_MANIFEST),
            alias,
            name,
            str(self.directory / "barrier"),
            phase,
            action,
        ]
        return subprocess.Popen(  # noqa: S603 - the test's own script
            [sys.executable, "-c", CONTROLLER, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def finish(self, process: subprocess.Popen[str]) -> dict[str, object]:
        stdout, stderr = process.communicate(timeout=300)
        self.assertEqual(process.returncode, 0, stderr[-3000:])
        result: dict[str, object] = json.loads(stdout.strip().splitlines()[-1])
        return result

    def test_two_controllers_creating_the_same_site_admit_one_run(self) -> None:
        controllers = {"a": "disposable", "b": "disposable-second"}
        for name, alias in controllers.items():
            prepared = self.finish(self.controller(name, alias, "prepare"))
            self.assertTrue(prepared["eligible"])
        time.sleep(1.1)
        racing = [self.controller(name, alias, "apply") for name, alias in controllers.items()]
        results = [self.finish(process) for process in racing]
        executions = [str(result["execution"]) for result in results]
        succeeded = [r for r in results if r["execution"] == Execution.SUCCEEDED]
        refused = [r for r in results if r["execution"] != Execution.SUCCEEDED]
        # At most one run changed the server; the other stopped under the lock before any
        # change, finding the lock taken, the other run's processes, or changed evidence.
        self.assertLessEqual(len(succeeded), 1, executions)
        for run in refused:
            self.assertIn(
                run["execution"],
                {Execution.LOCK_CONFLICT, Execution.OTHER_RUN_ACTIVE, Execution.DRIFT},
                executions,
            )
        self.assertEqual(sorted(self.units()), sorted(str(r["unit"]) for r in results))
        self.assertEqual(
            self.administer("getent passwd sshop | wc -l").strip(), str(len(succeeded))
        )
        for run in succeeded:
            self.assertEqual(run["status"], Status.SUCCEEDED, run["failure"])
            # The refused controller's fresh review finds the site the other one created.
            name = "a" if refused[0] is results[0] else "b"
            review = self.finish(self.controller(name, controllers[name], "review"))
            self.assertEqual((review["eligible"], review["no_changes"]), (True, True), review)

    def test_a_site_run_and_a_package_refresh_racing_admit_one(self) -> None:
        controllers = {"a": ("disposable", "site"), "b": ("disposable-second", "metadata_refresh")}
        for name, (alias, action) in controllers.items():
            prepared = self.finish(self.controller(name, alias, "prepare", action))
            self.assertTrue(prepared["eligible"])
        stamp = "stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null; true"
        before = self.administer(stamp)
        time.sleep(1.1)
        racing = [
            self.controller(name, alias, "apply", action)
            for name, (alias, action) in controllers.items()
        ]
        site, refresh = (self.finish(process) for process in racing)
        executions = [site["execution"], refresh["execution"]]
        succeeded = [run for run in (site, refresh) if run["execution"] == Execution.SUCCEEDED]
        self.assertLessEqual(len(succeeded), 1, executions)
        for run in (site, refresh):
            if run["execution"] != Execution.SUCCEEDED:
                self.assertIn(
                    run["execution"],
                    {Execution.LOCK_CONFLICT, Execution.OTHER_RUN_ACTIVE},
                    executions,
                )
        created = site["execution"] == Execution.SUCCEEDED
        self.assertEqual(self.administer("getent passwd sshop | wc -l").strip(), str(int(created)))
        refreshed = refresh["execution"] == Execution.SUCCEEDED
        self.assertEqual(self.administer(stamp) != before, refreshed)
