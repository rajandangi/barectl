"""The independent controller process the native controller-loss suites start
(docs/wordpress.md#applying-an-installation)."""

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
