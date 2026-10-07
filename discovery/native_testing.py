"""Separate controller processes for native reconstruction acceptance tests."""

import json
import os
import subprocess
import sys
from pathlib import Path

SETTINGS = ("HOST", "PORT", "USER", "KEY", "KNOWN_HOSTS")
CONFIGURED = all(os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in SETTINGS)


def setting(name: str) -> str:
    return os.environ[f"BARECTL_SSH_TEST_{name}"]


_CONTROLLER = """
import json
import os
import sys
from dataclasses import asdict
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest = sys.argv[1:4]
finish_identifier = sys.argv[4] if len(sys.argv) > 4 else ""
qualified_php = len(sys.argv) > 5 and sys.argv[5] == "qualified-php-fixture"
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
from discovery.fakes import current, run_worker
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from servers.models import Server
from sites.services import request_site_preparation

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
finished = None
if finish_identifier:
    for codename in ("view_siteplan", "prepare_siteplan", "apply_siteplan"):
        user.user_permissions.add(Permission.objects.get(codename=codename))
    site = next(site for site in snapshot.sites.value if site.identifier == finish_identifier)
    gate = (patch("bootstrap.php_supply.qualified", return_value=True)
            if qualified_php else nullcontext())
    with gate:
        request_site_preparation(server, user, site.identifier, site.server_names,
                                 php_version=site.php_version,
                                 convention_revision=site.convention_revision)
        run_worker()
    plan = ConfigurationPlan.objects.get()
    assert plan.eligible and "Finish" in plan.intent
    client.post(f"/plans/{plan.pk}/apply/", secure=True)
    run_worker()
    run = ApplyRun.objects.get()
    finished = {"execution": run.execution, "verification": run.verification,
                "changes": list(plan.site_files.filter(preimage_absent=True)
                                .values_list("role", flat=True))}
    snapshot = current(server).collected
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
    "finished": finished,
}))
"""


def reconstruct(
    directory: Path,
    ssh_config: Path,
    manifest: Path,
    *,
    finish_identifier: str = "",
    qualified_php: bool = False,
) -> dict[str, object]:
    """Migrate an empty controller and discover using its own key.

    ``qualified_php`` opens only the public PHP delivery gate for a disposable source
    qualification fixture's Finish preparation. Native source admission remains real.
    """
    directory.mkdir()
    result = subprocess.run(  # noqa: S603 - fixed test script and test fixture paths
        [
            sys.executable,
            "-c",
            _CONTROLLER,
            str(directory / "db.sqlite3"),
            str(ssh_config),
            str(manifest),
            finish_identifier,
            "qualified-php-fixture" if qualified_php else "",
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
