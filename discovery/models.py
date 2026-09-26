from collections.abc import Sequence
from typing import ClassVar, NamedTuple, override

from django.db import models
from django.db.models import Q
from django.db.models.expressions import Combinable

from servers.aliases import ALIAS_MAX_LENGTH
from servers.models import Server


class DiscoveryAttempt(models.Model):
    """One queued run of connection verification and read-only discovery for a server.

    Attempts are kept separately from the server registration and from the snapshots they
    publish, so a failed attempt never replaces earlier observations.
    """

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    ACTIVE: ClassVar[tuple[Status, Status]] = (Status.QUEUED, Status.RUNNING)

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="discovery_attempts")
    # The alias the attempt connects with, recorded when it was queued.
    ssh_alias = models.CharField("SSH alias", max_length=ALIAS_MAX_LENGTH)
    status = models.CharField(max_length=10, choices=Status, default=Status.QUEUED)
    queued_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # Operator-facing explanation of a failure. Never raw exception or remote output.
    failure = models.TextField(blank=True)
    # The verified host key, such as "ssh-ed25519 SHA256:…". Public information.
    host_key = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["-queued_at", "-pk"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            # Repeated registration or verification requests cannot start competing jobs.
            models.UniqueConstraint(
                fields=["server"],
                condition=Q(status__in=["queued", "running"]),
                name="discovery_one_active_attempt_per_server",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} discovery of {self.ssh_alias}"

    @property
    def is_active(self) -> bool:
        return self.status in self.ACTIVE


class ObservationStatus(models.TextChoices):
    OBSERVED = "observed", "Observed"
    # The file or command exists but the SSH user may not read or run it.
    INACCESSIBLE = "inaccessible", "Inaccessible"
    ABSENT = "absent", "Absent"
    # Present but not in a form Barectl can interpret.
    UNSUPPORTED = "unsupported", "Unsupported"


class CapacityObservation(NamedTuple):
    status: str
    status_label: str
    source: str
    warning: str


class DiscoverySnapshot(models.Model):
    """Observations published by one successful attempt, as they were at collection time."""

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="snapshots")
    attempt = models.OneToOneField(
        DiscoveryAttempt, on_delete=models.CASCADE, related_name="snapshot"
    )
    collected_at = models.DateTimeField()
    os_status = models.CharField(max_length=12, choices=ObservationStatus)
    # The remote file the OS observation was read from.
    os_source = models.CharField(max_length=100, blank=True)
    os_pretty_name = models.CharField(max_length=200, blank=True)
    os_name = models.CharField(max_length=200, blank=True)
    os_id = models.CharField(max_length=100, blank=True)
    os_version_id = models.CharField(max_length=100, blank=True)
    os_warning = models.TextField(blank=True)
    arch_status = models.CharField(max_length=12, choices=ObservationStatus)
    # The machine hardware name reported by uname, such as "x86_64".
    arch_value = models.CharField(max_length=100, blank=True)
    arch_source = models.CharField(max_length=100, blank=True)
    arch_warning = models.TextField(blank=True)
    cpu_status = models.CharField(max_length=12, choices=ObservationStatus)
    # The available processing units reported by nproc. Null unless observed.
    cpu_count = models.PositiveIntegerField(null=True, blank=True)
    cpu_source = models.CharField(max_length=100, blank=True)
    cpu_warning = models.TextField(blank=True)
    memory_status = models.CharField(max_length=12, choices=ObservationStatus)
    # Total memory in bytes, converted from MemTotal in kB. Null unless observed.
    memory_bytes = models.BigIntegerField(null=True, blank=True)
    memory_source = models.CharField(max_length=100, blank=True)
    memory_warning = models.TextField(blank=True)
    filesystem_status = models.CharField(max_length=12, choices=ObservationStatus)
    # Root filesystem capacity in bytes, from df -B1. Null unless observed.
    filesystem_size_bytes = models.BigIntegerField(null=True, blank=True)
    filesystem_avail_bytes = models.BigIntegerField(null=True, blank=True)
    filesystem_source = models.CharField(max_length=100, blank=True)
    filesystem_warning = models.TextField(blank=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["-collected_at", "-pk"]

    @override
    def __str__(self) -> str:
        return f"Snapshot of {self.server} at {self.collected_at:%Y-%m-%d %H:%M}"

    @property
    def capacity(self) -> list[CapacityObservation]:
        """The capacity observations, in display order."""
        return [
            CapacityObservation(
                self.arch_status,
                self.get_arch_status_display(),
                self.arch_source,
                self.arch_warning,
            ),
            CapacityObservation(
                self.cpu_status, self.get_cpu_status_display(), self.cpu_source, self.cpu_warning
            ),
            CapacityObservation(
                self.memory_status,
                self.get_memory_status_display(),
                self.memory_source,
                self.memory_warning,
            ),
            CapacityObservation(
                self.filesystem_status,
                self.get_filesystem_status_display(),
                self.filesystem_source,
                self.filesystem_warning,
            ),
        ]
