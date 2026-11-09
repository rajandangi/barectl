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

from operations.recovery_testing import assert_abrupt_run

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

_CONTROLLER = """
import json
import os
import pathlib
import time
from datetime import timedelta
import django
from config import settings
settings.DATABASES['default']['NAME'] = os.environ['RECOVERY_DATABASE']
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
django.setup()
from django.core.management import call_command
from django.contrib.auth.models import User
from django.utils import timezone
from discovery.services import read_discovery
from discovery.fakes import run_worker
from operations import engine, native, services
from operations.models import (
    ADMISSION_CENTISECONDS, ChangePreparation, ChangeReview, ChangeRun, RemoteOperation)
from operations.services import request_prepare, request_apply
from servers.models import Server
from servers.registration import save_server
from servers.ssh_config import resolve_alias
from discovery import ssh
from sites.change import SLUG
mode = os.environ['RECOVERY_MODE']

def snapshot_of(run):
    return {
        'pk': run.pk, 'status': str(run.status), 'execution': str(run.execution),
        'result_reason': run.result_reason, 'failure': run.failure,
        'verification': str(run.verification), 'progress_stage': run.progress_stage,
        'unit': run.unit_name, 'dispatched': run.dispatched_at is not None,
        'kind_slug': run.review.kind_slug, 'consent': str(run.review.consent),
        'document': run.review.document, 'preparation': run.review.preparation_id,
    }

def held_worker(operation_id, **changes):
    marker = pathlib.Path(os.environ['RECOVERY_MARKER'])
    if os.environ['RECOVERY_HOLD'] == 'before':
        marker.write_text(str(operation_id))
        while True:
            time.sleep(0.2)
    changed = original_dispatch(operation_id, **changes)
    marker.write_text(str(operation_id))
    while True:
        time.sleep(0.2)

if mode == 'worker':
    if os.environ.get('RECOVERY_HOLD'):
        original_dispatch = engine.lifecycle.dispatch
        engine.lifecycle.dispatch = held_worker
    call_command('db_worker', batch=True, startup_delay=False, interval=0, verbosity=0)
else:
    if mode == 'discover':
        call_command('migrate', verbosity=0, interactive=False)
        user = User.objects.create_superuser(username='operator')
        server = Server(name='Recovery', ssh_alias='recovery')
        save_server(server, user=user)
        run_worker()
        snapshot = read_discovery(server).snapshot
        if snapshot is None:
            raise AssertionError('The controller did not discover the native server.')
        with ssh.connect(resolve_alias(settings.SSH_CONFIG_PATH, 'recovery')) as shell:
            unit = os.environ['RECOVERY_UNIT']
            evidence = native.inspect(shell, unit)
            outcome = engine.read_result(shell, unit)
        from jobs.presentation import present as present_jobs
        jobs = present_jobs(snapshot, server, may_view_changes=True)
        sites = snapshot.collected.sites.value
        print(json.dumps({
            'sites': [{'identifier': row.identifier, 'runtime': row.php_version,
                       'state': row.state, 'uid': row.account.uid if row.account else None}
                      for row in sites],
            'runtimes': [row.entry for row in snapshot.collected.runtimes if row.manageable],
            'preparations': ChangePreparation.objects.count(), 'runs': ChangeRun.objects.count(),
            'native_result': outcome.result_class if outcome else None,
            'unit_populated': evidence.populated,
            'jobs': [
                {'title': row.title, 'sites': list(row.sites), 'summary': row.summary,
                 'result_class': row.result_class}
                for group in jobs.groups for row in group.rows
            ],
        }))
    elif mode in ('recover', 'check', 'close'):
        call_command('migrate', verbosity=0, interactive=False)
        user = User.objects.get(username='operator')
        run = ChangeRun.objects.select_related('review').get(pk=int(os.environ['RECOVERY_RUN']))
        if mode == 'recover' and run.status == 'running':
            RemoteOperation.objects.filter(pk=run.pk).update(
                started_at=timezone.now() - engine.STALE_AFTER - timedelta(minutes=1))
            services.read_run(run.pk)
        elif mode == 'check':
            if not services.request_check(run.pk):
                raise AssertionError('No check was queued: ' + run.status)
            run_worker()
        elif mode == 'close':
            if os.environ.get('RECOVERY_FENCE_CLOCK') == '1':
                # Move the review's own clock origin back so its fixed fifteen-minute
                # admission deadline is in the past; the server is not restarted.
                ChangeReview.objects.filter(pk=run.review_id).update(
                    uptime_centiseconds=-ADMISSION_CENTISECONDS,
                    admission_deadline_centiseconds=0,
                    admission_expires_at=timezone.now())
            if not services.request_closure(run.pk, user):
                raise AssertionError(
                    'No close was queued: ' + run.status + '/' + run.execution)
            run_worker()
        run = ChangeRun.objects.select_related('review').get(pk=run.pk)
        print(json.dumps(snapshot_of(run)))
    else:
        call_command('migrate', verbosity=0, interactive=False)
        user = User.objects.create_superuser(username='operator')
        server = Server(name='Recovery', ssh_alias='recovery')
        save_server(server, user=user)
        run_worker()
        snapshot = read_discovery(server).snapshot
        if snapshot is None:
            raise AssertionError('The controller did not discover the native server.')
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
            'run': requested.run.pk,
        }))
"""


class ControllerRecoveryMixin(ScenarioTestCase):
    """Controller host helpers shared by the abrupt-termination items."""

    layer = "L1"
    exclusive = True
    prefix = "s3"

    def controller(self, environment: dict[str, str], *, timeout: float = 75) -> dict[str, object]:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", _CONTROLLER],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            self.fail(
                f"The controller exited {result.returncode}:\n{result.stdout}\n{result.stderr}"
            )
        value = json.loads(result.stdout.splitlines()[-1])
        if not isinstance(value, dict):
            self.fail("The controller did not report its observed state.")
        return value

    def recovery_environment(self, root: Path) -> dict[str, str]:
        target = self.target()
        configuration = root / "ssh_config"
        configuration.write_text(
            f"Host recovery\n  HostName {target.hostname}\n  Port {target.port}\n"
            f"  User {target.user}\n  IdentityFile {target.identity_files[0]}\n"
            f"  UserKnownHostsFile {target.known_hosts_files[0]}\n",
            encoding="utf-8",
        )
        return os.environ | {
            "BARECTL_SSH_CONFIG": str(configuration),
            "BARECTL_SSH_KNOWN_HOSTS": str(target.known_hosts_files[0]),
            "SSH_AUTH_SOCK": "",
            "RECOVERY_DATABASE": str(root / "controller-a.sqlite3"),
        }

    def start_worker(
        self, environment: dict[str, str], *, hold: str = "", marker: Path | None = None
    ) -> subprocess.Popen[str]:
        extra = {"RECOVERY_MODE": "worker"}
        if hold:
            extra.update({"RECOVERY_HOLD": hold, "RECOVERY_MARKER": str(marker)})
        return subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", _CONTROLLER],
            env=environment | extra,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def wait_marker(self, worker: subprocess.Popen[str], marker: Path) -> None:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if marker.exists():
                return
            if worker.poll() is not None:
                _, stderr = worker.communicate(timeout=5)
                self.fail(f"The worker stopped before the interruption point:\n{stderr}")
            time.sleep(0.02)
        self.fail("The worker did not reach the interruption point.")

    def kill_worker(self, worker: subprocess.Popen[str]) -> None:
        if worker.poll() is None:
            worker.send_signal(signal.SIGKILL)
        worker.communicate(timeout=10)
        self.assertEqual(worker.returncode, -signal.SIGKILL)

    def submissions(self) -> list[str]:
        """The barectl native units that ever ran on this server, one per submission."""
        return self.native(
            "journalctl --no-pager -o verbose -u 'barectl-apply-*' 2>/dev/null "
            "| sed -n 's/^ *_SYSTEMD_UNIT=//p' | grep '^barectl-apply-' | sort -u || true"
        ).splitlines()

    def loaded_units(self) -> list[str]:
        return self.native(
            "systemctl list-units 'barectl-apply-*.service' --all --no-legend --no-pager || true"
        ).splitlines()

    def freeze_during_body(self, unit: str) -> None:
        """Freeze the unit as soon as it prints its first stage line."""
        self.native(
            "deadline=$(( $(date +%s) + 30 )); "
            'while [ "$(systemctl show -p MainPID --value '
            + shlex.quote(unit)
            + ')" = 0 ]; do [ $(date +%s) -lt $deadline ] || exit 1; sleep .02; done; '
            "while [ $(date +%s) -lt $deadline ]; do "
            "journalctl --no-pager -o cat -u " + shlex.quote(unit) + " "
            "| grep -q '^barectl-stage ' && break; "
            "systemctl is-active --quiet " + shlex.quote(unit) + " || "
            '{ echo "the body ended before it could be interrupted"; exit 1; }; '
            "sleep .02; done; "
            "systemctl kill --kill-whom=all --signal=STOP " + shlex.quote(unit) + "; "
            "pid=$(systemctl show -p MainPID --value " + shlex.quote(unit) + "); "
            "stop_deadline=$(( $(date +%s) + 10 )); "
            "while :; do "
            "state=$(sed -n 's/^State:[[:space:]]*\\([A-Z]\\).*/\\1/p' "
            "/proc/$pid/status 2>/dev/null); "
            '[ "$state" = T ] && exit 0; '
            'kill -0 "$pid" 2>/dev/null || '
            '{ echo "process exited before SIGSTOP"; exit 1; }; '
            "[ $(date +%s) -lt $stop_deadline ] || "
            '{ echo "process did not stop"; exit 1; }; '
            "sleep .02; done",
            timeout=45,
        )


@tag(SCENARIO_TAG)
class HttpSiteControllerRecovery(ControllerRecoveryMixin, ScenarioTestCase):
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
                    "pid=$(systemctl show -p MainPID --value " + shlex.quote(str(unit)) + "); "
                    "systemctl kill --kill-whom=all --signal=STOP " + shlex.quote(str(unit)) + "; "
                    "stop_deadline=$(( $(date +%s) + 10 )); "
                    "while :; do "
                    "state=$(sed -n 's/^State:[[:space:]]*\\([A-Z]\\).*/\\1/p' "
                    "/proc/$pid/status 2>/dev/null); "
                    '[ "$state" = T ] && exit 0; '
                    'kill -0 "$pid" 2>/dev/null || '
                    '{ echo "process exited before SIGSTOP"; exit 1; }; '
                    "[ $(date +%s) -lt $stop_deadline ] || "
                    '{ echo "process did not stop"; exit 1; }; '
                    "sleep .02; done",
                    timeout=45,
                )
                stopped = True
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
                jobs = discovered["jobs"]
                if not isinstance(jobs, list):
                    self.fail("The fresh controller did not report Jobs rows.")
                self.assertIn(
                    {
                        "title": "Create PHP site",
                        "sites": ["s3recovery"],
                        "summary": "Finished",
                        "result_class": "succeeded",
                    },
                    jobs,
                )
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


@tag(SCENARIO_TAG)
class WorkerKilledBeforeDispatch(ControllerRecoveryMixin):
    """A worker killed after review but before dispatch leaves nothing submitted."""

    def test_worker_killed_after_review_before_dispatch_changes_nothing(self) -> None:
        """An undispatched run is failed as interrupted, with one retry and no submission."""
        with tempfile.TemporaryDirectory(prefix="barectl-s3-before-") as directory:
            root = Path(directory)
            environment = self.recovery_environment(root) | {"RECOVERY_MODE": "prepare"}
            baseline = self.submissions()
            prepared = self.controller(environment)
            run = prepared["run"]
            self.assertIsInstance(run, int)
            worker = self.start_worker(environment, hold="before", marker=root / "before-dispatch")
            try:
                self.wait_marker(worker, root / "before-dispatch")
                self.assertIsNone(worker.poll(), "The worker finished before it was killed.")
                self.kill_worker(worker)
            finally:
                if worker.poll() is None:
                    worker.kill()
                    worker.communicate(timeout=10)
            self.assertEqual(
                self.submissions(), baseline, "An undispatched run reached the server."
            )
            self.assertEqual(self.loaded_units(), [])
            recovered = self.controller(
                environment | {"RECOVERY_MODE": "recover", "RECOVERY_RUN": str(run)},
                timeout=120,
            )
            self.assertEqual(recovered["status"], "failed", recovered)
            self.assertEqual(recovered["execution"], "not_submitted", recovered)
            self.assertFalse(recovered["dispatched"], recovered)
            self.assertIn("before it submitted anything", str(recovered["failure"]))
            assert_abrupt_run(
                self,
                recovered,
                result="Stopped",
                action="Try again",
                action_kind="again",
                changed_possible=False,
            )
            self.assertEqual(self.submissions(), baseline, "Recovery submitted the run again.")


@tag(SCENARIO_TAG)
class WorkerKilledAfterDispatch(ControllerRecoveryMixin):
    """A worker killed after dispatch can no longer prove that nothing ran."""

    def test_worker_killed_after_dispatch_is_reconciled_as_unknown_without_submission(
        self,
    ) -> None:
        """A dispatched run is never retried; evidence ends unknown and offers the server."""
        with tempfile.TemporaryDirectory(prefix="barectl-s3-after-") as directory:
            root = Path(directory)
            environment = self.recovery_environment(root) | {"RECOVERY_MODE": "prepare"}
            baseline = self.submissions()
            prepared = self.controller(environment)
            run = prepared["run"]
            self.assertIsInstance(run, int)
            worker = self.start_worker(environment, hold="after", marker=root / "after-dispatch")
            try:
                self.wait_marker(worker, root / "after-dispatch")
                self.assertIsNone(worker.poll(), "The worker finished before it was killed.")
                self.kill_worker(worker)
            finally:
                if worker.poll() is None:
                    worker.kill()
                    worker.communicate(timeout=10)
            self.assertEqual(self.submissions(), baseline, "The held worker submitted a unit.")
            self.assertEqual(self.loaded_units(), [])
            recovered = self.controller(
                environment | {"RECOVERY_MODE": "recover", "RECOVERY_RUN": str(run)},
                timeout=120,
            )
            self.assertTrue(recovered["dispatched"], recovered)
            self.assertEqual(recovered["status"], "reconciling", recovered)
            assert_abrupt_run(
                self,
                recovered,
                result="Checking what happened",
                action="Check what happened",
                action_kind="check",
                changed_possible=True,
            )
            checked = self.controller(
                environment | {"RECOVERY_MODE": "check", "RECOVERY_RUN": str(run)},
                timeout=120,
            )
            self.assertTrue(checked["dispatched"], checked)
            self.assertEqual(checked["status"], "reconciling", checked)
            self.assertEqual(checked["execution"], "not_found", checked)
            assert_abrupt_run(
                self,
                checked,
                result="Checking what happened",
                action="Check what happened",
                action_kind="check",
                changed_possible=True,
            )
            closed = self.controller(
                environment
                | {
                    "RECOVERY_MODE": "close",
                    "RECOVERY_RUN": str(run),
                    "RECOVERY_FENCE_CLOCK": "1",
                },
                timeout=120,
            )
            self.assertEqual(closed["status"], "failed", closed)
            self.assertEqual(closed["execution"], "outcome_unknown", closed)
            assert_abrupt_run(
                self,
                closed,
                result="Outcome unknown",
                action="Open the server",
                action_kind="link",
                changed_possible=True,
            )
            self.assertEqual(self.submissions(), baseline, "Recovery submitted the run again.")


@tag(SCENARIO_TAG)
class ServerStoppedDuringBody(ControllerRecoveryMixin):
    """A server stopped mid-body loses its transient unit and is never replayed."""

    def test_server_stopped_during_a_body_is_reconciled_as_unknown_without_replay(self) -> None:
        """A stopped server loses the transient unit; one submission stays one submission."""
        with tempfile.TemporaryDirectory(prefix="barectl-s3-stop-") as directory:
            root = Path(directory)
            environment = self.recovery_environment(root) | {"RECOVERY_MODE": "prepare"}
            prepared = self.controller(environment)
            raw_unit = prepared["unit"]
            if not isinstance(raw_unit, str):
                self.fail("The controller did not report its native unit.")
            unit = raw_unit
            run = prepared["run"]
            self.assertIsInstance(run, int)
            baseline = self.submissions()
            worker = self.start_worker(environment)
            try:
                self.freeze_during_body(unit)
                before = self.submissions()
                self.assertEqual(len(set(before) - set(baseline)), 1, before)
                self.stop_for(5)
                deadline = time.monotonic() + 20
                while worker.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.1)
            finally:
                if worker.poll() is None:
                    worker.kill()
                worker.communicate(timeout=10)
            recovered = self.controller(
                environment | {"RECOVERY_MODE": "recover", "RECOVERY_RUN": str(run)},
                timeout=120,
            )
            self.assertTrue(recovered["dispatched"], recovered)
            self.assertEqual(recovered["status"], "reconciling", recovered)
            assert_abrupt_run(
                self,
                recovered,
                result="Checking what happened",
                action="Check what happened",
                action_kind="check",
                changed_possible=True,
            )
            checked = self.controller(
                environment | {"RECOVERY_MODE": "check", "RECOVERY_RUN": str(run)},
                timeout=120,
            )
            self.assertEqual(checked["status"], "reconciling", checked)
            self.assertEqual(checked["execution"], "not_found", checked)
            # The container stop is a userspace restart, not a new kernel boot, so the
            # journal's stage lines without a result line are the evidence: the run
            # reached the server and stopped silently.
            self.assertIn("no result line", str(checked["failure"]).lower())
            self.assertIn("what it changed is unknown", str(checked["failure"]).lower())
            assert_abrupt_run(
                self,
                checked,
                result="Checking what happened",
                action="Check what happened",
                action_kind="check",
                changed_possible=True,
            )
            closed = self.controller(
                environment
                | {
                    "RECOVERY_MODE": "close",
                    "RECOVERY_RUN": str(run),
                    "RECOVERY_FENCE_CLOCK": "1",
                },
                timeout=120,
            )
            self.assertEqual(closed["status"], "failed", closed)
            self.assertEqual(closed["execution"], "outcome_unknown", closed)
            assert_abrupt_run(
                self,
                closed,
                result="Outcome unknown",
                action="Open the server",
                action_kind="link",
                changed_possible=True,
            )
            self.assertEqual(self.submissions(), before, "Recovery submitted the run again.")
            self.assertEqual(self.loaded_units(), [])
