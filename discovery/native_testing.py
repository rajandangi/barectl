"""Separate controller processes for native reconstruction acceptance tests."""

import json
import os
import subprocess
import sys
from pathlib import Path

_CONTROLLER = """
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest = sys.argv[1:]
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
from bootstrap.models import ApplyRun, PlanPreparation
from discovery.fakes import current, run_worker
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from servers.models import Server

call_command("migrate", verbosity=0)
user = get_user_model().objects.create_user("viewer")
for codename in ("view_server", "view_siteobservation"):
    user.user_permissions.add(Permission.objects.get(codename=codename))
server = Server.objects.create(name="Reconstructed", ssh_alias="disposable")
request_discovery(server)
run_worker()
attempt = DiscoveryAttempt.objects.get()
snapshot = current(server).collected
client = Client()
client.force_login(user)
page = client.get(f"/servers/{server.pk}/sites/", secure=True)
print(json.dumps({
    "status": attempt.status,
    "failure": attempt.failure,
    "sites": [asdict(site) for site in snapshot.sites.value],
    "components": [asdict(component) for component in snapshot.components],
    "page_status": page.status_code,
    "page": page.content.decode(),
    "runs": ApplyRun.objects.count(),
    "preparations": PlanPreparation.objects.count(),
}))
"""


def reconstruct(directory: Path, ssh_config: Path, manifest: Path) -> dict[str, object]:
    """Migrate an empty SQLite database and discover using this controller's own key."""
    directory.mkdir()
    result = subprocess.run(  # noqa: S603 - fixed test script and test fixture paths
        [
            sys.executable,
            "-c",
            _CONTROLLER,
            str(directory / "db.sqlite3"),
            str(ssh_config),
            str(manifest),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
        env={**os.environ, "SSH_AUTH_SOCK": ""},
    )
    if result.returncode:
        raise AssertionError(result.stderr[-4000:])
    value: object = json.loads(result.stdout.strip().splitlines()[-1])
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise AssertionError("The controller did not return a reconstruction report.")
    return value
