"""S10 admits exactly one of two independent controllers racing for the native lock."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import tag

from .docker import DockerError
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

_CONTROLLER = """
import json
import os
import time

import django
from config import settings

settings.DATABASES["default"]["NAME"] = os.environ["RACE_DATABASE"]
os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
django.setup()

from django.contrib.auth.models import User
from django.core.management import call_command
from discovery import ssh
from discovery.fakes import run_worker
from operations import engine
from operations.models import ChangeReview
from operations.services import request_apply, request_prepare
from servers.models import Server
from servers.registration import save_server
from servers.ssh_config import resolve_alias
from sites.change import SLUG

identifier = os.environ["RACE_IDENTIFIER"]
mode = os.environ["RACE_MODE"]
call_command("migrate", verbosity=0, interactive=False)
user, _ = User.objects.get_or_create(
    username="operator", defaults={"is_staff": True, "is_superuser": True}
)
server = Server.objects.filter(name="Race").first()
if server is None:
    server = Server(name="Race", ssh_alias="race")
    save_server(server, user=user)
run_worker()


def prepare():
    preparation = request_prepare(server, user, SLUG, inputs={
        "version": 1, "selection": "php84", "identifier": identifier,
        "names": [identifier + ".example.com"],
    })
    if preparation is None:
        raise AssertionError("Preparation was not queued.")
    run_worker()
    preparation.refresh_from_db()
    return preparation.review


if mode == "prepare":
    review = prepare()
    print(json.dumps({"eligible": review.eligible, "no_changes": review.no_changes}))
elif mode == "review":
    review = prepare()
    print(json.dumps({"eligible": review.eligible, "no_changes": review.no_changes}))
else:
    review = ChangeReview.objects.filter(
        preparation__server=server, eligible=True
    ).order_by("-pk").first()
    if review is None:
        raise AssertionError("No eligible review to apply.")
    requested = request_apply(review, user, acknowledged=True)
    if requested.run is None:
        raise AssertionError(requested.problem)
    unit = requested.run.unit_name
    run_worker()
    with ssh.connect(resolve_alias(settings.SSH_CONFIG_PATH, "race")) as shell:
        deadline = time.monotonic() + 120
        outcome = engine.read_result(shell, unit)
        while outcome is None and time.monotonic() < deadline:
            time.sleep(0.1)
            outcome = engine.read_result(shell, unit)
    if outcome is None:
        raise AssertionError("No native result for " + unit)
    print(json.dumps({"unit": unit, "class": outcome.result_class, "reason": outcome.reason}))
"""


@tag(SCENARIO_TAG)
class TwoControllerNativeLock(ScenarioTestCase):
    """Two controllers with their own databases race one server; the lock admits one."""

    layer = "L1"
    exclusive = True
    prefix = "s10"

    def test_two_controllers_racing_admit_one_run_and_refuse_the_other(self) -> None:
        target = self.target()
        with tempfile.TemporaryDirectory(prefix="barectl-s10-") as directory:
            root = Path(directory)
            configuration = root / "ssh_config"
            configuration.write_text(
                f"Host race\n  HostName {target.hostname}\n  Port {target.port}\n"
                f"  User {target.user}\n  IdentityFile {target.identity_files[0]}\n"
                f"  UserKnownHostsFile {target.known_hosts_files[0]}\n",
                encoding="utf-8",
            )
            common = os.environ | {
                "BARECTL_SSH_CONFIG": str(configuration),
                "BARECTL_SSH_KNOWN_HOSTS": str(target.known_hosts_files[0]),
                "SSH_AUTH_SOCK": "",
            }
            databases = {
                "a": root / "controller-a.sqlite3",
                "b": root / "controller-b.sqlite3",
            }
            prepared = {
                name: self.controller(
                    common
                    | {
                        "RACE_DATABASE": str(databases[name]),
                        "RACE_MODE": "prepare",
                        "RACE_IDENTIFIER": "s10alpha" if name == "a" else "s10beta",
                    }
                )
                for name in ("a", "b")
            }
            self.assertTrue(prepared["a"]["eligible"], prepared["a"])
            self.assertTrue(prepared["b"]["eligible"], prepared["b"])
            self.assertFalse(prepared["a"]["no_changes"], prepared["a"])

            first = subprocess.Popen(  # noqa: S603 - the test's own controller
                [sys.executable, "-c", _CONTROLLER],
                env=common
                | {
                    "RACE_DATABASE": str(databases["a"]),
                    "RACE_MODE": "apply",
                    "RACE_IDENTIFIER": "s10alpha",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                try:
                    self.await_native_lock()
                except DockerError:
                    if first.poll() is not None:
                        stdout, stderr = first.communicate()
                        self.fail(
                            "The first controller never held the lock:\n" + stdout + stderr[-3000:]
                        )
                    raise
                second = self.controller(
                    common
                    | {
                        "RACE_DATABASE": str(databases["b"]),
                        "RACE_MODE": "apply",
                        "RACE_IDENTIFIER": "s10beta",
                    }
                )
                self.assertEqual(second["class"], "lock_busy", second)
                winner = self.finish(first)
                self.assertEqual(winner["class"], "succeeded", winner)
                self.native("test -d /var/www/s10alpha; ! test -e /var/www/s10beta")
                fresh = self.controller(
                    common
                    | {
                        "RACE_DATABASE": str(databases["b"]),
                        "RACE_MODE": "review",
                        "RACE_IDENTIFIER": "s10beta",
                    }
                )
                self.assertTrue(fresh["eligible"], fresh)
                self.assertFalse(fresh["no_changes"], fresh)
            finally:
                if first.poll() is None:
                    first.kill()
                first.communicate(timeout=10)

    def await_native_lock(self, timeout: float = 70) -> None:
        """Wait until the running controller holds the server's mutation lock.

        The probe reads /proc/locks for an exclusive flock on the lock file's inode; taking
        the lock to test it could make the controller's own non-blocking acquire refuse.
        """
        self.native(
            "deadline=$(( $(date +%s) + 60 )); "
            "until [ -e /run/lock/barectl/mutation.lock ] && "
            "awk -v inode=$(stat -c %i /run/lock/barectl/mutation.lock) "
            '\'$2 == "FLOCK" && $4 == "WRITE" { split($6, id, ":"); '
            "if (id[3] == inode) found = 1 } END { exit !found }' /proc/locks; do "
            "[ $(date +%s) -lt $deadline ] || exit 1; sleep .05; done",
            timeout=timeout,
        )

    def controller(self, environment: dict[str, str]) -> dict[str, object]:
        result = subprocess.run(  # noqa: S603 - the test's own controller
            [sys.executable, "-c", _CONTROLLER],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=200,
        )
        if result.returncode != 0:
            self.fail("The controller failed:\n" + result.stderr[-3000:])
        value = json.loads(result.stdout.strip().splitlines()[-1])
        if not isinstance(value, dict):
            self.fail("The controller did not report its state.")
        return value

    def finish(self, process: subprocess.Popen[str]) -> dict[str, object]:
        stdout, stderr = process.communicate(timeout=200)
        self.assertEqual(process.returncode, 0, stderr[-3000:])
        value = json.loads(stdout.strip().splitlines()[-1])
        if not isinstance(value, dict):
            self.fail("The controller did not report its native result.")
        return value
