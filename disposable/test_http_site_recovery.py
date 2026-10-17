"""S3 reconstructs a site after its controller dies during native execution."""

import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from django.test import tag

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

_CONTROLLER = """
import json
import os
import django
from config import settings
settings.DATABASES['default']['NAME'] = os.environ['RECOVERY_DATABASE']
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
django.setup()
from django.core.management import call_command
from django.contrib.auth.models import User
from discovery.services import read_discovery
from discovery.fakes import run_worker
from operations import engine, native
from operations.models import ChangePreparation, ChangeRun
from operations.services import request_prepare, request_apply
from servers.models import Server
from servers.registration import save_server
from servers.ssh_config import resolve_alias
from discovery import ssh
from sites.change import SLUG
mode = os.environ['RECOVERY_MODE']
if mode == 'worker':
    call_command('db_worker', batch=True, startup_delay=False, interval=0, verbosity=0)
else:
    call_command('migrate', verbosity=0, interactive=False)
    user = User.objects.create_superuser(username='operator')
    server = Server(name='Recovery', ssh_alias='recovery')
    save_server(server, user=user)
    run_worker()
    snapshot = read_discovery(server).snapshot
    if snapshot is None:
        raise AssertionError('The controller did not discover the native server.')
    if mode == 'prepare':
        preparation = request_prepare(server, user, SLUG, inputs={
            'version': 1, 'selection': 'php84', 'identifier': 's3recovery',
            'names': ['s3recovery.example.com'],
        })
        if preparation is None:
            raise AssertionError('Preparation was not queued.')
        run_worker()
        preparation.refresh_from_db()
        review = preparation.review
        if not review.eligible:
            raise AssertionError(review.document)
        requested = request_apply(review, user, acknowledged=True)
        if requested.run is None:
            raise AssertionError(requested.problem)
        print(json.dumps({
            'unit': requested.run.unit_name, 'identity': review.document['identity'],
        }))
    else:
        with ssh.connect(resolve_alias(settings.SSH_CONFIG_PATH, 'recovery')) as shell:
            unit = os.environ['RECOVERY_UNIT']
            evidence = native.inspect(shell, unit)
            outcome = engine.read_result(shell, unit)
        sites = snapshot.collected.sites.value
        print(json.dumps({
            'sites': [{'identifier': row.identifier, 'runtime': row.php_version,
                       'state': row.state, 'uid': row.account.uid if row.account else None}
                      for row in sites],
            'runtimes': [row.entry for row in snapshot.collected.runtimes if row.manageable],
            'preparations': ChangePreparation.objects.count(), 'runs': ChangeRun.objects.count(),
            'native_result': outcome.result_class if outcome else None,
            'unit_populated': evidence.populated,
        }))
"""


@tag(SCENARIO_TAG)
class HttpSiteControllerRecovery(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s3"

    def test_native_site_creation_survives_worker_death_and_fresh_controller_discovery(
        self,
    ) -> None:
        target = self.target()
        with tempfile.TemporaryDirectory(prefix="barectl-s3-") as directory:
            root = Path(directory)
            configuration = root / "ssh_config"
            configuration.write_text(
                f"Host recovery\n  HostName {target.hostname}\n  Port {target.port}\n"
                f"  User {target.user}\n  IdentityFile {target.identity_files[0]}\n"
                f"  UserKnownHostsFile {target.known_hosts_files[0]}\n",
                encoding="utf-8",
            )
            environment = os.environ | {
                "BARECTL_SSH_CONFIG": str(configuration),
                "BARECTL_SSH_KNOWN_HOSTS": str(target.known_hosts_files[0]),
                "SSH_AUTH_SOCK": "",
                "RECOVERY_DATABASE": str(root / "controller-a.sqlite3"),
                "RECOVERY_MODE": "prepare",
            }
            prepared = self.controller(environment)
            unit = prepared["unit"]
            self.assertIsInstance(unit, str)
            worker = subprocess.Popen(  # noqa: S603
                [sys.executable, "-c", _CONTROLLER],
                env=environment | {"RECOVERY_MODE": "worker"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stopped = False
            try:
                self.native(
                    "deadline=$(( $(date +%s) + 30 )); "
                    'while [ "$(systemctl show -p MainPID --value '
                    + shlex.quote(str(unit))
                    + ')" = 0 ]; do [ $(date +%s) -lt $deadline ] || exit 1; sleep .02; done; '
                    "systemctl kill --kill-whom=all --signal=STOP " + shlex.quote(str(unit)),
                    timeout=35,
                )
                stopped = True
                self.native(
                    "pid=$(systemctl show -p MainPID --value "
                    + shlex.quote(str(unit))
                    + "); test \"$(sed -n 's/^State:[[:space:]]*\\([A-Z]\\).*/\\1/p' "
                    '/proc/$pid/status)" = T'
                )
                from operations import engine

                with self.shell() as shell:
                    self.assertIsNone(engine.read_result(shell, str(unit)))
                self.assertIsNone(worker.poll(), "The controller finished before interruption.")
                worker.send_signal(signal.SIGKILL)
                worker.communicate(timeout=10)
                self.assertEqual(worker.returncode, -signal.SIGKILL)
                self.native(
                    "systemctl kill --kill-whom=all --signal=CONT " + shlex.quote(str(unit))
                )
                stopped = False
                deadline = time.monotonic() + 60
                with self.shell() as shell:
                    outcome = engine.read_result(shell, str(unit))
                    while outcome is None and time.monotonic() < deadline:
                        time.sleep(0.1)
                        outcome = engine.read_result(shell, str(unit))
                self.assertIsNotNone(outcome, self.native(f"journalctl -u {unit} -n 40"))
                if outcome is None:
                    self.fail("The native unit did not report its outcome.")
                self.assertEqual(outcome.result_class, "succeeded")
                second_database = root / "controller-b.sqlite3"
                self.assertFalse(second_database.exists())
                discovered = self.controller(
                    environment
                    | {
                        "RECOVERY_DATABASE": str(second_database),
                        "RECOVERY_MODE": "discover",
                        "RECOVERY_UNIT": str(unit),
                    }
                )
                self.assertEqual(discovered["preparations"], 0)
                self.assertEqual(discovered["runs"], 0)
                self.assertEqual(discovered["native_result"], "succeeded")
                self.assertFalse(discovered["unit_populated"])
                runtimes = discovered["runtimes"]
                if not isinstance(runtimes, list):
                    self.fail("The fresh controller did not report runtime observations.")
                self.assertIn("php84", runtimes)
                self.assertEqual(
                    discovered["sites"],
                    [
                        {
                            "identifier": "s3recovery",
                            "runtime": "php84",
                            "state": "managed",
                            "uid": prepared["identity"],
                        }
                    ],
                )
                response = json.loads(
                    self.native(
                        "curl --fail --silent -H 'Host: s3recovery.example.com' http://127.0.0.1/"
                    )
                )
                self.assertEqual(response["uid"], prepared["identity"])
            finally:
                try:
                    if stopped:
                        self.native(
                            "systemctl kill --kill-whom=all --signal=CONT " + shlex.quote(str(unit))
                        )
                finally:
                    if worker.poll() is None:
                        worker.kill()
                    worker.communicate(timeout=10)

    def controller(self, environment: dict[str, str]) -> dict[str, object]:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", _CONTROLLER],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=75,
        )
        value = json.loads(result.stdout.splitlines()[-1])
        if not isinstance(value, dict):
            self.fail("The controller did not report its observed state.")
        return value
