"""Local feedback for read-only checks, independent of authoritative snapshots.

docs/ssh-connections.md#workflow
"""

from dataclasses import dataclass
from enum import StrEnum

from django.utils import timezone

from discovery.ssh import CommandResult, RemoteShell

from .models import RemoteOperation


class CheckStage(StrEnum):
    CONNECT = "connect"
    SYSTEM = "system"
    SOFTWARE = "software"
    SITES = "sites"
    PROTECTION = "protection"
    INSPECT = "inspect"
    REVIEW = "review"
    AFFECTED_SITES = "affected_sites"
    SAVE = "save"


DISCOVERY_STEPS = (
    (CheckStage.CONNECT, "Connect securely"),
    (CheckStage.SYSTEM, "Read system details"),
    (CheckStage.SOFTWARE, "Check installed software"),
    (CheckStage.SITES, "Read sites and background work"),
    (CheckStage.PROTECTION, "Read security and backups"),
    (CheckStage.SAVE, "Save the server details"),
)
PREPARATION_STEPS = (
    (CheckStage.CONNECT, "Connect securely"),
    (CheckStage.INSPECT, "Read server configuration"),
    (CheckStage.REVIEW, "Build your confirmation"),
    (CheckStage.AFFECTED_SITES, "Check affected sites"),
    (CheckStage.SAVE, "Finish checking"),
)


@dataclass(frozen=True)
class CheckStep:
    label: str
    state: str
    current: bool


@dataclass(frozen=True)
class CheckView:
    label: str
    steps: tuple[CheckStep, ...]
    reads: int
    elapsed: str
    waiting: bool
    quiet: bool
    token: str


def _duration(seconds: int) -> str:
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes}m {seconds}s" if minutes else f"{seconds}s"


def present_check(operation: RemoteOperation) -> CheckView:
    steps = (
        DISCOVERY_STEPS if operation.kind == RemoteOperation.Kind.DISCOVERY else PREPARATION_STEPS
    )
    waiting = operation.status == RemoteOperation.Status.QUEUED
    current = next(
        (index for index, (stage, _) in enumerate(steps) if stage == operation.check_stage), 0
    )
    now = timezone.now()
    elapsed = max(0, int((now - (operation.started_at or operation.queued_at)).total_seconds()))
    updated = operation.check_updated_at or operation.started_at or operation.queued_at
    return CheckView(
        label="Waiting for the background worker" if waiting else steps[current][1],
        steps=tuple(
            CheckStep(
                label,
                "Waiting"
                if waiting or index > current
                else "Reading"
                if index == current
                else "Done",
                not waiting and index == current,
            )
            for index, (_, label) in enumerate(steps)
        ),
        reads=operation.check_reads,
        elapsed=_duration(elapsed),
        waiting=waiting,
        quiet=not waiting and (now - updated).total_seconds() >= 15,
        token=f"{operation.pk}:{operation.status}:{operation.check_stage}:{operation.check_reads}",
    )


class CheckProgress:
    def __init__(self, operation: RemoteOperation) -> None:
        self.operation_id = operation.pk
        self.stage = CheckStage.CONNECT
        self.reads = 0

    def report(self, stage: CheckStage) -> None:
        self.stage = stage
        self._save()

    def _save(self) -> None:
        RemoteOperation.objects.filter(
            pk=self.operation_id, status=RemoteOperation.Status.RUNNING
        ).update(
            check_stage=self.stage,
            check_reads=self.reads,
            check_updated_at=timezone.now(),
        )

    def read_finished(self) -> None:
        self.reads += 1
        self._save()


@dataclass
class CheckReader:
    shell: RemoteShell
    progress: CheckProgress

    @property
    def host_key(self) -> str:
        return self.shell.host_key

    def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
        result = self.shell.run(command, stdin=stdin)
        self.progress.read_finished()
        return result
