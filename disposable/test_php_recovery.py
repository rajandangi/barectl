"""Interrupted PHP admission and partial configuration recover from native evidence only."""

import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from django.test import tag

from operations import engine, native
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from sites.change import CREATE_SITE
from sites.observation import python_command
from sites.php_change import SET_SITE_PHP, SOURCE

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

# Captures the legitimate both-READY window, kills only the owned apply unit, and records the
# live and persisted native state an independent controller must reconstruct (ADR 0038).
_WATCHER = r"""
import json, os, pathlib, signal, socket, sys, time
unit = sys.argv[1]
result = pathlib.Path('/run/s339recover-watch.json')
cgroup = pathlib.Path('/sys/fs/cgroup/system.slice') / unit / 'cgroup.procs'
def state():
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(2)
        client.connect('/run/haproxy/s339recover/admin.sock')
        client.sendall(b'show servers state\n')
        data = b''
        while block := client.recv(65536): data += block
    return data.decode()
def ready(text):
    rows = [line.split() for line in text.splitlines() if line and not line.startswith('#')]
    return {row[3]: row[6] for row in rows if len(row) >= 7} == {'php84':'4', 'php85':'4'}
end = time.monotonic() + 70
while time.monotonic() < end:
    observed = state()
    if ready(observed) and cgroup.exists():
        pids = [int(value) for value in cgroup.read_text().split()]
        for pid in pids:
            try: os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError: pass
        captured = state()
        persisted = pathlib.Path('/var/lib/haproxy/sites/s339recover.state').read_text()
        result.write_text(json.dumps({'live':captured, 'persisted':persisted,
                                    'captured':ready(captured), 'pids':pids}))
        for pid in pids:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        break
else:
    result.write_text(json.dumps({
        'captured':False, 'problem':'Native both-READY window was missed.'}))
"""

# A fresh controller with its own empty database: it must reconstruct the interrupted
# transition from native configuration and the running API, then finish or reverse it through
# public services and the worker. No private operation history is imported.
_CONTROLLER = r"""
import json, os, django
from config import settings
settings.DATABASES['default']['NAME'] = os.environ['RECOVERY_DATABASE']
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
django.setup()
from django.core.management import call_command
from django.contrib.auth.models import User
from discovery.services import read_discovery
from discovery.fakes import run_worker
from operations.models import ChangeReview, ChangeRun
from operations.services import request_prepare, request_apply
from servers.models import Server
from servers.registration import save_server
from sites.php_change import SLUG
identifier = os.environ['RECOVERY_IDENTIFIER']
selection = os.environ['RECOVERY_SELECTION']
call_command('migrate', verbosity=0, interactive=False)
user = User.objects.create_superuser(username='operator')
server = Server(name='Recovery', ssh_alias='recovery')
save_server(server, user=user)
run_worker()
snapshot = read_discovery(server).snapshot
if snapshot is None: raise AssertionError('No fresh discovery.')
site = next(row for row in snapshot.collected.sites.value if row.identifier == identifier)
prior = {'reviews':ChangeReview.objects.count(), 'runs':ChangeRun.objects.count(),
         'state':str(site.state)}
preparation = request_prepare(server, user, SLUG, inputs={
    'version':1, 'selection':selection, 'identifier':identifier})
if preparation is None: raise AssertionError('No recovery preparation.')
run_worker()
preparation.refresh_from_db()
review = preparation.review
if not review.eligible: raise AssertionError(review.document)
requested = request_apply(review, user, acknowledged=True)
if requested.run is None: raise AssertionError(requested.problem)
run_worker()
requested.run.refresh_from_db()
print(json.dumps({'prior':prior, 'execution':str(requested.run.execution),
                  'verification':str(requested.run.verification), 'status':requested.run.status}))
"""


def fresh_controller_recovery(
    test: ScenarioTestCase, identifier: str, selection: str
) -> dict[str, object]:
    """Finish or reverse a transition from a fresh controller with an empty database."""
    target = test.target()
    with tempfile.TemporaryDirectory(prefix="barectl-php-recovery-") as directory:
        root = Path(directory)
        configuration = root / "ssh_config"
        configuration.write_text(
            f"Host recovery\n  HostName {target.hostname}\n  Port {target.port}\n"
            f"  User {target.user}\n  IdentityFile {target.identity_files[0]}\n"
            f"  UserKnownHostsFile {target.known_hosts_files[0]}\n"
        )
        database = root / "fresh.sqlite3"
        test.assertFalse(database.exists())
        result = subprocess.run(  # noqa: S603 - fixed fresh-controller fixture
            [sys.executable, "-c", _CONTROLLER],
            env=os.environ
            | {
                "BARECTL_SSH_CONFIG": str(configuration),
                "BARECTL_SSH_KNOWN_HOSTS": str(target.known_hosts_files[0]),
                "SSH_AUTH_SOCK": "",
                "RECOVERY_DATABASE": str(database),
                "RECOVERY_IDENTIFIER": identifier,
                "RECOVERY_SELECTION": selection,
            },
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            test.fail(
                "Fresh controller exited "
                + str(result.returncode)
                + ":\n"
                + result.stdout
                + "\n"
                + result.stderr
            )
        value: object = json.loads(result.stdout.splitlines()[-1])
        if not isinstance(value, dict):
            test.fail("The fresh controller printed no outcome: " + result.stdout)
        return {str(key): value[key] for key in value}


@tag(SCENARIO_TAG)
class SitePHPControllerRecovery(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s339recover"

    def test_both_ready_interruption_is_finished_without_previous_controller_history(self) -> None:
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs("php84", self.prefix, (self.prefix + ".example.com",)),
        )
        php = (
            "<?php file_put_contents('/var/www/s339recover/private/tmp/effects', "
            "'once'.PHP_EOL, FILE_APPEND|LOCK_EX); echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;"
        )
        self.native(
            "printf %s " + shlex.quote(php) + " >/var/www/s339recover/current/public/recovery.php"
        )
        fingerprint = (
            "sha256sum /etc/caddy/sites/s339recover.caddy /etc/haproxy/sites/s339recover.cfg; "
            "find /var/www/s339recover -type f -not -path '*/logs/*' "
            "-not -path '*/private/tmp/effects' "
            "-not -path '*/bin/php' -not -path '*/bin/composer' -not -path '*/bin/wp' "
            "-exec sha256sum {} + | sort; "
            "find /var/www/s339recover/bin /usr/local/bin -maxdepth 1 -type l "
            "-printf '%p %l\\n' | sort; "
            "systemctl show caddy.service haproxy-site@s339recover.service "
            "-p MainPID -p InvocationID"
        )
        before = self.native(fingerprint)
        inputs = PreparationInputs("php85", self.prefix)
        with self.shell() as shell:
            draft = SET_SITE_PHP.review(SET_SITE_PHP.inspect(shell, inputs), inputs)
            self.assertTrue(draft.eligible, draft.refusals)
            review = ChangeReview(
                document=draft.document,
                sites_read=draft.sites_read,
                sites_digest=engine._sites_digest(shell, draft),
            )
            context = engine.BodyContext(
                native.new_unit_name(), draft.boot_id, int(draft.uptime_centiseconds or 0) + 90000
            )
            self.addCleanup(
                self.native,
                "systemctl kill --kill-whom=all --signal=KILL "
                + shlex.quote(context.unit)
                + " >/dev/null 2>&1 || true",
            )
            body = SET_SITE_PHP.body(draft.document, context)
            path = engine.body_path(context.unit)
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, str(draft.document["body_sha256"]))),
                    stdin=body.source,
                ).exit_status,
                0,
            )
            self.native("printf %s " + shlex.quote(_WATCHER) + " >/run/s339recover-watch.py")
            self.native(
                "systemd-run --collect --unit=s339recover-watcher -- python3 "
                "/run/s339recover-watch.py " + shlex.quote(context.unit)
            )
            self.addCleanup(self.native, "systemctl stop s339recover-watcher.service || true")
            payload = engine.payload(SET_SITE_PHP, review, context, body, path)
            self.assertEqual(
                shell.run(
                    shlex.join(native.submission(context.unit, payload, collect=True))
                ).exit_status,
                0,
            )
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            raw = self.native(
                "if test -f /run/s339recover-watch.json; then cat /run/s339recover-watch.json; fi"
            )
            if raw:
                break
            with self.shell() as shell:
                outcome = engine.read_result(shell, context.unit)
            if outcome is not None:
                probe = SOURCE + (
                    "\nimport traceback\ntry:\n value=php_state('s339recover')"
                    "\n print(canonical({'complete':value['complete'], 'digest':value['digest']}))"
                    "\nexcept Exception: traceback.print_exc(file=sys.stdout)\n"
                )
                details = self.native(python_command(probe, ()))
                self.fail(
                    "The apply completed before native interruption: "
                    + outcome.result_class
                    + "/"
                    + outcome.reason
                    + details
                    + self.native("journalctl --no-pager -o cat -u " + context.unit)
                )
            time.sleep(0.05)
        else:
            self.fail("The native interruption watcher did not finish.")
        captured = json.loads(raw)
        self.assertTrue(captured["captured"], captured)
        sys.stdout.write("Native interrupted PHP admission: " + json.dumps(captured) + "\n")
        sys.stdout.flush()
        self.assertEqual(self.states(captured["live"]), {"php84": "4", "php85": "4"})
        self.assertEqual(self.states(captured["persisted"]), {"php84": "4", "php85": "5"})
        with self.shell() as shell:
            journal = engine.read_journal(shell, context.unit, list(draft.stages))
        # The killed unit is unloaded and left no result line, but its stage lines show
        # that it reached the server and how far it got.
        self.assertIsNone(journal.line)
        self.assertIn(journal.stage, draft.stages[2:])
        recovered = fresh_controller_recovery(self, self.prefix, "php85")
        self.assertEqual(recovered["prior"], {"reviews": 0, "runs": 0, "state": "partly_applied"})
        self.assertEqual(recovered["status"], "succeeded", recovered)
        self.assertEqual(recovered["execution"], "succeeded", recovered)
        self.assertEqual(recovered["verification"], "passed", recovered)
        self.assertEqual(self.native(fingerprint), before)
        self.native("test ! -d /etc/php-fpm/sites/s339recover/php84")
        self.assertEqual(
            self.native(
                "curl --fail --silent -X POST -H 'Host: s339recover.example.com' "
                "http://127.0.0.1/recovery.php"
            ),
            "8.5",
        )
        self.assertEqual(self.native("cat /var/www/s339recover/private/tmp/effects"), "once\n")

    @staticmethod
    def states(text: str) -> dict[str, str]:
        rows = (line.split() for line in text.splitlines() if line and not line.startswith("#"))
        return {row[3]: row[6] for row in rows if len(row) >= 7}


# The exact canonical convention of the second runtime, minus its pools directory and three
# files, with the service never started: what a crash during target staging or an interrupted
# source cleanup leaves (ADR 0038).
# Two native shapes an interrupted `remove_stopped_php` actually leaves, in cleanup order:
# after it unlinked the first three files, and after it removed the pools directory.
_MID_CLEANUP_SECOND_RUNTIME = r"""
import sys as _ps
_site = _ps.argv[1]
_settings = setting(_site, [_site + ".example.com"], "php85")
_base = "/etc/php-fpm/sites/" + _site + "/php85"
serving_directory(_base + "/pools")
_files = site_fpm_files(_settings)
write_new(_base + "/pools/diagnostic.conf", _files[_base + "/pools/diagnostic.conf"], 0o644)
print(canonical({"base": _base}))
"""
_EMPTY_SECOND_RUNTIME = r"""
import sys as _ps
_base = "/etc/php-fpm/sites/" + _ps.argv[1] + "/php85"
serving_directory(_base)
print(canonical({"base": _base}))
"""


@tag(SCENARIO_TAG)
class SitePHPPartialFilesystemRecoveryCase(ScenarioTestCase):
    """Shared setup for the two partial-runtime recovery cases."""

    layer = "L1"
    exclusive = True
    prefix = "s339partial"

    def prepare(self) -> None:
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs("php84", self.prefix, (self.prefix + ".example.com",)),
        )

    def stage_second_runtime(self, script: str, present: str, absent: str) -> None:
        self.native(python_command(SOURCE + "\n" + script, (self.prefix,)))
        self.assertEqual(
            self.native(f"{present} && {absent} && printf staged"), "staged", (present, absent)
        )
        self.assertEqual(
            self.native(
                f"systemctl show --value -p ActiveState php-fpm-site-php85@{self.prefix}.service"
            ).strip(),
            "inactive",
        )

    def serving(self) -> str:
        return self.native(
            "curl --fail --silent -H "
            + shlex.quote("Host: " + self.prefix + ".example.com")
            + " http://127.0.0.1/"
        )


@tag(SCENARIO_TAG)
class SitePHPPartialFilesystemReverse(SitePHPPartialFilesystemRecoveryCase):
    """A partially removed runtime directory is reversed from native evidence."""

    def test_a_fresh_controller_reverses_a_partially_removed_runtime(self) -> None:
        self.prepare()
        base = f"/etc/php-fpm/sites/{self.prefix}/php85"
        self.stage_second_runtime(
            _MID_CLEANUP_SECOND_RUNTIME,
            f"test -f {base}/pools/diagnostic.conf",
            f"test ! -e {base}/php.ini && test ! -e {base}/php-fpm.conf"
            f" && test ! -e {base}/pools/{self.prefix}.conf",
        )
        # A fresh controller reverses the interrupted cleanup, keeping the serving runtime.
        reverted = fresh_controller_recovery(self, self.prefix, "php84")
        self.assertEqual(reverted["prior"], {"reviews": 0, "runs": 0, "state": "partly_applied"})
        self.assertEqual(reverted["status"], "succeeded", reverted)
        self.assertEqual(reverted["verification"], "passed", reverted)
        self.assertEqual(self.native(f"test -e {base} || printf gone"), "gone")
        self.assertIn('"8.4', self.serving())


@tag(SCENARIO_TAG)
class SitePHPPartialFilesystemFinish(SitePHPPartialFilesystemRecoveryCase):
    """An empty runtime directory is completed and selected from native evidence."""

    def test_a_fresh_controller_finishes_an_empty_runtime_and_selects_it(self) -> None:
        self.prepare()
        base = f"/etc/php-fpm/sites/{self.prefix}/php85"
        self.stage_second_runtime(
            _EMPTY_SECOND_RUNTIME,
            f"test -d {base} && test ! -e {base}/pools",
            f"test ! -e {base}/php.ini && test ! -e {base}/php-fpm.conf",
        )
        finished = fresh_controller_recovery(self, self.prefix, "php85")
        self.assertEqual(finished["prior"], {"reviews": 0, "runs": 0, "state": "partly_applied"})
        self.assertEqual(finished["status"], "succeeded", finished)
        self.assertEqual(finished["verification"], "passed", finished)
        self.assertEqual(
            self.native(f"systemctl is-active php-fpm-site-php85@{self.prefix}.service").strip(),
            "active",
        )
        self.assertEqual(
            self.native(f"test -e /etc/php-fpm/sites/{self.prefix}/php84 || printf gone"), "gone"
        )
        self.assertIn('"8.5', self.serving())
