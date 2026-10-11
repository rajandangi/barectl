"""A simulated server's systemd, sudo and journal for the change engine's tests.

``EngineSystemd`` answers the commands of ``operations.native`` and the engine's own
journal read on a ``discovery.fakes.FakeServer``. Tests choose the payload's result line
and exit status, how long the unit runs, where the connection is lost, and what the
closure probe reports. A successful cleanup clears the units its payload names. It
establishes nothing about real systemd, flock or journald; the native suites do.
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import override
from unittest import mock

from discovery.fakes import DiscoveryTestCase, FakeServer
from discovery.ssh import CommandResult, ConnectionFailed
from servers.models import Server

from . import engine
from .models import ChangePreparation, ChangeReview, ChangeRun

BOOT_ID = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
UPTIME_CENTISECONDS = 500025
PREPARE_PERMISSIONS = ("view_server", "view_changes", "change_site")
APPLY_PERMISSIONS = ("view_changes", "change_shared")
_UNIT = re.compile(r"barectl-apply-[0-9a-f]{32}\.service")
_SUBMITTED_UNIT = re.compile(r"--unit=(barectl-apply-[0-9a-f]{32}\.service)")
# The reviewed target's unit and invocation are plain validated arguments to its script.
_TARGETS = re.compile(r"(barectl-apply-[0-9a-f]{32}\.service)\|[0-9a-f]{32}\|")


@dataclass
class EngineUnit:
    """A transient unit the simulated systemd started, as the engine's evidence sees it."""

    # Inspections that still find it running before it finishes and collects itself.
    running: int = 0
    exit_status: int = 0
    # The structured result line's class; ``None`` when the payload reported nothing.
    result_class: str | None = None
    reason: str = ""
    invocation_id: str = "0f" * 16
    # The unit stays in systemd after it finished, instead of collecting itself.
    retained: bool = False
    body_path: str = ""

    def journal(self) -> str:
        if self.result_class is None:
            return ""
        line = {"class": self.result_class}
        if self.reason:
            line["reason"] = self.reason
        return f"{engine.RESULT_PREFIX}{json.dumps(line)}\n"

    def terminal_report(self) -> str:
        failed = self.exit_status != 0 or (
            self.result_class is not None and self.result_class != "succeeded"
        )
        state = (
            "ActiveState=failed\nSubState=failed"
            if failed
            else "ActiveState=active\nSubState=exited"
        )
        result = "exit-code" if failed else "success"
        return (
            f"LoadState=loaded\n{state}\nResult={result}\n"
            f"ExecMainCode=1\nExecMainStatus={self.exit_status}\n"
            f"InvocationID={self.invocation_id}\npopulated 0\n"
        )

    def running_report(self) -> str:
        return (
            "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n"
            "ExecMainCode=0\nExecMainStatus=0\n"
            f"InvocationID={self.invocation_id}\npopulated 1\n"
        )


def finished_unit(invocation: int, *, failed: bool = False) -> EngineUnit:
    """A retained unit a cleanup review offers to clear."""
    return EngineUnit(
        0,
        1 if failed else 0,
        None,
        invocation_id=f"{invocation:032x}",
        retained=True,
    )


_NOT_FOUND_REPORT = (
    "LoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=success\n"
    "ExecMainCode=0\nExecMainStatus=0\nInvocationID=\npopulated 0\n"
)


@dataclass
class EngineSystemd:
    root: bool = False
    sudo_allowed: bool = True
    # Finished units counted as retained besides ``units``, which list with no details.
    retained: int = 0
    # The retained-unit reads fail, as they do when systemd cannot answer.
    retained_fail: bool = False
    # What a submitted unit reports: the structured result line's class and reason.
    result_class: str = "succeeded"
    reason: str = ""
    # systemd-run refuses the unit and creates nothing.
    reject: bool = False
    # The connection ends after systemd-run started the unit, before its answer arrives.
    lose_acknowledgement: bool = False
    # The connection ends at this inspection (counted from 1), or the worker stops there.
    lose_at_inspection: int = 0
    stop_worker_at_inspection: int = 0
    boot_id: str = BOOT_ID
    # The monotonic clock the review's uptime read and the closure probe report.
    uptime_centiseconds: int = UPTIME_CENTISECONDS
    # The closure probe's exit status: 0 took the lock, 10 held, 11 unsafe.
    probe_exit: int = 0
    # Barectl units whose control groups have processes, as the probe counts them.
    probe_populated: int = 0
    # Whether Certbot's renewal service has processes, as the probe reads it.
    probe_renewal: bool = False
    # Called when systemd starts a submitted unit, to change what later reads find.
    on_submit: Callable[[], None] | None = None
    units: dict[str, EngineUnit] = field(default_factory=dict)
    # Every started unit's journal entry, which outlives the collected unit.
    journal_units: dict[str, EngineUnit] = field(default_factory=dict)
    submissions: list[str] = field(default_factory=list)
    journals: list[str] = field(default_factory=list)
    probes: int = 0
    inspections: int = 0
    stage_fail: bool = False
    staged_bodies: dict[str, bytes] = field(default_factory=dict)
    staged_digests: list[str] = field(default_factory=list)
    remote: FakeServer | None = None

    def answer(self, remote: FakeServer) -> None:
        self.remote = remote
        if self._answer not in remote.answers:
            remote.answers.append(self._answer)

    def _answer(self, command: str) -> CommandResult | None:
        for answer in (
            self._identity_answer,
            self._staging_answer,
            self._evidence_answer,
            self._execution_answer,
        ):
            if (result := answer(command)) is not None:
                return result
        return None

    def _identity_answer(self, command: str) -> CommandResult | None:
        if command == "id -u":
            return CommandResult(0, "0\n" if self.root else "1000\n")
        if command.startswith(("sudo -n -l /usr/bin/systemd-run ", "sudo -n -l /usr/bin/sh -c ")):
            return CommandResult(0 if self.sudo_allowed else 1, "")
        if command.startswith("sudo -n -l /usr/bin/rm -f -- /run/lock/barectl/body-"):
            return CommandResult(0 if self.sudo_allowed else 1, "")
        if command.startswith("sudo -n -l /usr/bin/journalctl -u barectl-apply-"):
            return CommandResult(0 if self.sudo_allowed else 1, "")
        if command == "cut -d' ' -f1 /proc/uptime | tr -d .":
            return CommandResult(0, f"{self.uptime_centiseconds}\n")
        return None

    def _staging_answer(self, command: str) -> CommandResult | None:
        if "/usr/bin/tee --" in command and "/run/lock/barectl/body-" in command:
            return self._stage(command)
        if command.startswith(
            (
                "sudo -n /usr/bin/rm -f -- /run/lock/barectl/body-",
                "/usr/bin/rm -f -- /run/lock/barectl/body-",
            )
        ):
            self.staged_bodies.pop(command.rsplit(" ", 1)[-1], None)
            return CommandResult(0, "")
        return None

    def _evidence_answer(self, command: str) -> CommandResult | None:
        if command == self.retained_units_command:
            return self._retained()
        if command.startswith("cat /proc/sys/kernel/random/boot_id; units=$(systemctl"):
            return self._retained_states()
        if command.startswith("cat /proc/sys/kernel/random/boot_id; systemctl show"):
            return self._inspect(command)
        if command.startswith(
            (
                "journalctl -u barectl-apply-",
                "/usr/bin/journalctl -u barectl-apply-",
                "sudo -n /usr/bin/journalctl -u barectl-apply-",
            )
        ):
            return self._journal(command)
        return None

    def _execution_answer(self, command: str) -> CommandResult | None:
        if command.startswith(("sudo -n /usr/bin/systemd-run ", "/usr/bin/systemd-run ")):
            return self._submit(command)
        if command.startswith(("/usr/bin/sh -c ", "sudo -n /usr/bin/sh -c ")):
            return self._probe(command)
        return None

    def _retained(self) -> CommandResult:
        lines = "".join(
            f"{name} loaded active exited Barectl reviewed apply\n"
            for name in [*self._synthetic(), *self.units]
        )
        return CommandResult(1 if self.retained_fail else 0, "" if self.retained_fail else lines)

    def _retained_states(self) -> CommandResult:
        if self.retained_fail:
            return CommandResult(1, "")
        reports = "".join(f"Id={name}\n{self._unit_report(name)}" for name in self.units)
        return CommandResult(0, f"{self.boot_id}\n{reports}")

    def _retained_units(self) -> str:
        return "systemctl list-units --all --plain --no-legend --type=service 'barectl-apply-*'"

    @property
    def retained_units_command(self) -> str:
        return self._retained_units()

    def _synthetic(self) -> list[str]:
        return [f"barectl-apply-{index:032x}.service" for index in range(self.retained)]

    def _unit_report(self, name: str) -> str:
        unit = self.units.get(name)
        if unit is None:
            return _NOT_FOUND_REPORT
        return unit.running_report() if unit.running > 0 else unit.terminal_report()

    def _submit(self, command: str) -> CommandResult:
        self.submissions.append(command)
        found = _SUBMITTED_UNIT.search(command)
        if found is None or self.reject:
            return CommandResult(1, "")
        unit = EngineUnit(
            exit_status=_EXIT_STATUSES.get(self.result_class, 0),
            result_class=self.result_class,
            reason=self.reason,
            body_path=next(
                iter(re.findall(r"/run/lock/barectl/body-[0-9a-f]{32}\.sh", command)), ""
            ),
        )
        self.units[found[1]] = unit
        self.journal_units[found[1]] = unit
        if unit.result_class == "succeeded":
            for name in _TARGETS.findall(command):
                self.units.pop(name, None)
        if self.on_submit is not None:
            self.on_submit()
        if self.lose_acknowledgement:
            raise ConnectionFailed("The connection to web.example.com ended.")
        return CommandResult(0, "")

    def _probe(self, command: str) -> CommandResult:
        self.probes += 1
        if self.probe_exit:
            return CommandResult(self.probe_exit, "")
        name = _UNIT.findall(command)[-1]
        loaded = "loaded" if name in self.units else "not-found"
        return CommandResult(
            0,
            f"{self.boot_id}\n{self.uptime_centiseconds}\npopulated {self.probe_populated}\n"
            f"{loaded}\nrenewal {int(self.probe_renewal)}\n",
        )

    def _inspect(self, command: str) -> CommandResult:
        self.inspections += 1
        if self.inspections == self.lose_at_inspection:
            raise ConnectionFailed("The connection to web.example.com ended.")
        if self.inspections == self.stop_worker_at_inspection:
            raise SystemExit(1)
        name = _UNIT.findall(command)[0]
        unit = self.units.get(name)
        if unit is None:
            report = f"Id={name}\n{_NOT_FOUND_REPORT}"
        elif unit.running > 0:
            unit.running -= 1
            report = f"Id={name}\n{unit.running_report()}"
        elif unit.retained:
            report = f"Id={name}\n{unit.terminal_report()}"
        else:
            # The unit collected itself when it finished; its evidence is the journal.
            del self.units[name]
            self.staged_bodies.pop(unit.body_path, None)
            report = f"Id={name}\n{_NOT_FOUND_REPORT}"
        return CommandResult(0, f"{self.boot_id}\n{report}")

    def _stage(self, command: str) -> CommandResult:
        path = next(iter(re.findall(r"/run/lock/barectl/body-[0-9a-f]{32}\.sh", command)), "")
        source = self.remote.current_stdin if self.remote is not None else None
        expected = re.search(r"= ([0-9a-f]{64}) \]", command)
        if (
            self.stage_fail
            or not path
            or source is None
            or expected is None
            or hashlib.sha256(source).hexdigest() != expected[1]
        ):
            return CommandResult(1, "")
        self.staged_bodies[path] = source
        self.staged_digests.append(hashlib.sha256(source).hexdigest())
        return CommandResult(0, "")

    def _journal(self, command: str) -> CommandResult:
        name = _UNIT.findall(command)[0]
        self.journals.append(command)
        unit = self.journal_units.get(name)
        if unit is None or unit.running > 0:
            return CommandResult(0, "")
        return CommandResult(0, unit.journal())


_EXIT_STATUSES = {
    "succeeded": 0,
    "refused": 1,
    "partial": 2,
    "failed": 3,
    "lock_busy": 10,
    "timed_out": 3,
}


class ChangeTestCase(DiscoveryTestCase):
    """The engine's workflow tests: a fake server whose systemd answers the adapter."""

    systemd: EngineSystemd

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = EngineSystemd()
        self.systemd.answer(self.remote)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.enterContext(mock.patch.object(engine, "POLL_INTERVAL", 0))

    @override
    def assert_read_only(self) -> None:
        # Besides reads, each run submits exactly one transient unit, never a second.
        units = [
            match[1]
            for command in self.remote.commands
            if (match := _SUBMITTED_UNIT.search(command))
            and command.startswith(("/usr/bin/systemd-run", "sudo -n /usr/bin/systemd-run"))
        ]
        self.assertEqual(len(units), len(set(units)), "A run was submitted twice")
        reads = [
            command
            for command in self.remote.commands
            if not command.startswith(("/usr/bin/systemd-run", "sudo -n /usr/bin/systemd-run"))
            and not command.startswith("sudo -n -l ")
            and not command.startswith("sudo -n /usr/bin/rm -f -- /run/lock/barectl/body-")
            and not command.startswith("sudo -n /usr/bin/journalctl -u ")
            and command not in {"id -u", self.systemd.retained_units_command}
            and not command.startswith("cat /proc/sys/kernel/random/boot_id")
            and not command.startswith("cut -d' ' -f1 /proc/uptime")
            and not command.startswith("journalctl -u ")
            and not command.startswith(("/usr/bin/sh -c ", "sudo -n /usr/bin/sh -c "))
        ]
        self.remote.commands[:] = reads
        super().assert_read_only()

    def prepare(
        self, kind: str = "cleanup_runs", *, perms: tuple[str, ...] = PREPARE_PERMISSIONS
    ) -> ChangePreparation:
        """Request a preparation as an operator with ``perms``, run the worker, return it."""
        self.sign_in_with(*perms)
        self.client.post(f"/servers/{self.server.pk}/changes/prepare/", {"kind": kind})
        self.run_worker()
        return ChangePreparation.objects.latest("queued_at", "pk")

    def change(self, kind: str = "cleanup_runs") -> ChangeReview:
        """Prepare ``kind`` and return its review, failing the test without one."""
        preparation = self.prepare(kind)
        review = ChangeReview.objects.filter(preparation=preparation).first()
        if review is None:
            self.fail(f"The preparation {preparation.pk} recorded no review.")
        return review

    def apply(self, review: ChangeReview | None = None) -> ChangeRun:
        review = review or self.change()
        self.sign_in_with(*APPLY_PERMISSIONS)
        fields = {"affected_sites": "on"} if review.consent == "shared" else {}
        self.client.post(f"/changes/{review.preparation_id}/apply/", fields)
        run = ChangeRun.objects.filter(review=review).first()
        if run is None:
            self.fail("No run was queued.")
        self.run_worker()
        return ChangeRun.objects.get(pk=run.pk)

    def check(self, run: ChangeRun) -> ChangeRun:
        self.client.post(f"/runs/{run.pk}/check/")
        self.run_worker()
        return ChangeRun.objects.get(pk=run.pk)
