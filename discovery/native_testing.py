"""Shared settings, ground-truth shell and fixture commands for the native acceptance tests."""

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from . import ssh
from .fakes import pool_config, site_config

SETTINGS = ("HOST", "PORT", "USER", "KEY", "KNOWN_HOSTS")
CONFIGURED = all(os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in SETTINGS)


def setting(name: str) -> str:
    return os.environ[f"BARECTL_SSH_TEST_{name}"]


FIXTURES = CONFIGURED and all(
    os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in ("CONTAINER", "UNPRIVILEGED_USER")
)


# Configuration, packages and running services that discovery must leave unchanged: a
# restarted service gets a new main process and activation time.
# Each account's systemd user manager, user@<uid>.service, starts and stops with its SSH
# sessions, as pam_systemd runs it on Ubuntu servers; it is session state, not the server's.
# systemd-udevd and the D-Bus activated services start and stop as the boot settles and as
# clients query them, so they are transient state too, not configuration Barectl changes.
_TRANSIENT_UNITS = "^user@|^systemd-udevd|^systemd-timedated|^systemd-hostnamed|^systemd-localed"
STATE_COMMAND = (
    "find /etc \"$HOME\" -xdev -printf '%p %s %T@ %m\\n' 2>/dev/null | sort | sha256sum; "
    "stat -c '%s %Y' /var/lib/dpkg/status; "
    "systemctl show -p Id -p MainPID -p ActiveEnterTimestamp "
    "$(systemctl list-units --type=service --state=running --no-legend --plain | cut -d' ' -f1 "
    f"| grep -vE '{_TRANSIENT_UNITS}')"
)


class NativeShell:
    """Ground truth through the controller's OpenSSH client, independent of Barectl.

    One multiplexed OpenSSH connection carries every command, checked against the same
    trusted known_hosts file.
    """

    host_key = ""

    def __init__(self, directory: Path) -> None:
        self.control = directory / "native"

    def options(self) -> list[str]:
        return [
            "-F",
            os.devnull,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={setting('KNOWN_HOSTS')}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={self.control}",
            "-o",
            "ControlPersist=60",
            "-i",
            setting("KEY"),
            "-p",
            setting("PORT"),
            "-l",
            setting("USER"),
            setting("HOST"),
        ]

    def run(self, command: str) -> ssh.CommandResult:
        result = subprocess.run(  # noqa: S603 - the tests' own commands
            ["ssh", *self.options(), command],  # noqa: S607 - OpenSSH on PATH
            capture_output=True,
            timeout=60,
            check=False,
        )
        return ssh.CommandResult(result.returncode, result.stdout.decode("utf-8", "replace"))

    def close(self) -> None:
        if self.control.exists():
            subprocess.run(  # noqa: S603 - fixed arguments
                ["ssh", *self.options()[:-1], "-O", "exit", setting("HOST")],  # noqa: S607
                capture_output=True,
                timeout=60,
                check=False,
            )


def write_file(path: str, content: str, mode: str) -> str:
    return f"printf %s {shlex.quote(content)} >{path} && chmod {mode} {path}"


def create_site(php: str, identifier: str = "alpha") -> str:
    """The administrator's own commands for a site that meets the convention."""
    user, boundary = f"s{identifier}", f"/var/www/{identifier}"
    source = f"/etc/nginx/sites-available/{identifier}.conf"
    names = (f"{identifier}.test", f"www.{identifier}.test")
    return " && ".join(
        (
            (
                f"useradd --home-dir {boundary} --no-create-home "
                f"--shell /usr/sbin/nologin --user-group {user}"
            ),
            f"install -d -o root -g root -m 755 {boundary}",
            f"install -d -o {user} -g www-data -m 750 {boundary}/public",
            f"install -d -o {user} -g {user} -m 700 {boundary}/private",
            write_file(source, site_config(identifier, names), "644"),
            f"ln -s {source} /etc/nginx/sites-enabled/{identifier}.conf",
            write_file(
                f"/etc/php/{php}/fpm/pool.d/{identifier}.conf", pool_config(identifier), "644"
            ),
            "nginx -t -q",
            f"php-fpm{php} -t",
            f"systemctl reload php{php}-fpm",
            f"for _ in $(seq 50); do test -S /run/php/{user}.sock && break; sleep 0.2; done",
            f"test -S /run/php/{user}.sock",
        )
    )


def remove_site(php: str, identifier: str) -> str:
    return "; ".join(
        (
            f"rm -f /etc/nginx/sites-enabled/{identifier}.conf",
            f"rm -f /etc/nginx/sites-available/{identifier}.conf",
            f"rm -f /etc/php/{php}/fpm/pool.d/{identifier}.conf",
            f"systemctl reload php{php}-fpm",
            f"rm -rf /var/www/{identifier}",
            f"id s{identifier} >/dev/null 2>&1 && userdel s{identifier}",
            "true",
        )
    )


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
