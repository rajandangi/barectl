"""Typed backup observations and the explicit read-only listing (Phase D #396).

Discovery stores one row per site with what native evidence shows. A **Check backups**
request stores the recovery points it read on its own request row, with the time it read
them; the next check replaces them. Nothing here is a second source of truth.
"""

from collections.abc import Sequence
from typing import ClassVar, override

from django.conf import settings
from django.db import models
from django.db.models.expressions import Combinable
from django.utils import timezone

from operations.models import RemoteOperation
from servers.models import Server


class BackupCheck(RemoteOperation):
    """One explicit read of one site's recovery points."""

    KIND: ClassVar[str] = RemoteOperation.Kind.BACKUP_CHECK
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    identifier = models.CharField(max_length=24)
    # The bounded listing: {"version": 1, "points": […], "outcome": …, "problem": …}.
    listing = models.JSONField(default=dict)
    checked_at = models.DateTimeField(null=True, blank=True)
    server: Server  # type: ignore[mutable-override]

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} backup check of {self.identifier}"


class BackupRetention(models.Model):
    """One site's retention policy, from the last verified read of its cleanup units (#404).

    It is a cached observation for the page, never authority: the next review, apply and
    cleanup all read the server's own units and payload again.
    """

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="backup_retentions")
    identifier = models.CharField(max_length=24)
    installed = models.BooleanField(default=False)
    days = models.PositiveSmallIntegerField(default=0)
    offsite = models.BooleanField(default=False)
    problem = models.TextField(blank=True)
    checked_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["server", "identifier"], name="one_backup_retention_per_site"
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        state = f"{self.days} days" if self.installed else "not set"
        return f"backup retention {state}: {self.identifier} on {self.server}"


class BackupSchedule(models.Model):
    """One site's last verified backup schedule, from native units and systemd (#402).

    It is a cached observation for the page, never authority: the next review and the native
    body re-read the server, and a next run is shown only when systemd reported one.
    """

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="backup_schedules")
    identifier = models.CharField(max_length=24)
    frequency = models.CharField(max_length=10, blank=True)
    at = models.CharField(max_length=5, blank=True)
    scope = models.CharField(max_length=10, blank=True)
    offsite = models.BooleanField(default=False)
    installed = models.BooleanField(default=False)
    timer_active = models.BooleanField(default=False)
    timer_enabled = models.BooleanField(default=False)
    service_active = models.BooleanField(default=False)
    next_elapse_us = models.BigIntegerField(default=0)
    last_trigger_us = models.BigIntegerField(default=0)
    last_start_us = models.BigIntegerField(default=0)
    last_exit_us = models.BigIntegerField(default=0)
    result = models.CharField(max_length=20, blank=True)
    exec_status = models.PositiveIntegerField(default=0)
    problem = models.TextField(blank=True)
    checked_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["server", "identifier"], name="one_backup_schedule_per_site"
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        state = "set" if self.installed else "not set"
        return f"backup schedule {state}: {self.identifier} on {self.server}"


class BackupIntegrity(models.Model):
    """One site's newest integrity finding for one location, from native result lines (#405).

    It is a cached observation for the page, never authority: the next Check backups and the
    next passive discovery replace it from the server's own journal.
    """

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="backup_integrity")
    identifier = models.CharField(max_length=24)
    location = models.CharField(max_length=8)
    result_class = models.CharField(max_length=20, blank=True)
    reason = models.CharField(max_length=40, blank=True)
    at = models.CharField(max_length=40, blank=True)
    point = models.CharField(max_length=16, blank=True)
    checked = models.PositiveSmallIntegerField(default=0)
    snapshots = models.PositiveSmallIntegerField(default=0)
    bytes = models.BigIntegerField(default=0)
    subset = models.CharField(max_length=8, blank=True)
    checked_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["server", "identifier", "location"],
                name="one_backup_integrity_per_site_location",
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"backup integrity {self.result_class or 'not checked'}: {self.identifier}"


class BackupExport(models.Model):
    """One approved export whose artifacts are in private controller staging (#409).

    It holds no file content and no server path: the token names a private directory and
    the download URL. The row expires; expiry, cancellation and a completed download remove
    the directory without connecting to the server.
    """

    class Status(models.TextChoices):
        READY = "ready", "Ready"
        CANCELLED = "cancelled", "Cancelled"
        EXPIRED = "expired", "Expired"

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="backup_exports")
    identifier = models.CharField(max_length=24)
    point = models.CharField(max_length=16)
    token = models.CharField(max_length=32, unique=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    status = models.CharField(max_length=10, choices=Status, default=Status.READY)
    files_bytes = models.BigIntegerField(default=0)
    database_bytes = models.BigIntegerField(default=0)
    files_served = models.BooleanField(default=False)
    database_served = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["-created_at", "-pk"]

    @override
    def __str__(self) -> str:
        return f"export of {self.identifier} on {self.server}"

    @property
    def has_files(self) -> bool:
        return self.files_bytes > 0

    @property
    def has_database(self) -> bool:
        return self.database_bytes > 0

    @property
    def complete(self) -> bool:
        return (not self.has_files or self.files_served) and (
            not self.has_database or self.database_served
        )

    @property
    def expired(self) -> bool:
        return self.status == self.Status.EXPIRED or self.expires_at <= timezone.now()


class BackupObservation(models.Model):
    """One site's backup setup and newest result, from one discovery snapshot."""

    snapshot = models.ForeignKey(
        "discovery.DiscoverySnapshot", on_delete=models.CASCADE, related_name="backups"
    )
    identifier = models.CharField(max_length=24)
    enabled = models.BooleanField(default=False)
    profile = models.CharField(max_length=200, blank=True)
    repository = models.BooleanField(default=False)
    server_key = models.BooleanField(default=False)
    database = models.BooleanField(default=False)
    database_problem = models.TextField(blank=True)
    problems = models.TextField(blank=True)
    # The newest safe result line: its class, when it ran, its scope and sizes.
    result_class = models.CharField(max_length=20, blank=True)
    result_reason = models.CharField(max_length=40, blank=True)
    result_scope = models.CharField(max_length=12, blank=True)
    result_origin = models.CharField(max_length=12, blank=True)
    result_at = models.CharField(max_length=40, blank=True)
    result_point = models.CharField(max_length=16, blank=True)
    result_snapshots = models.PositiveSmallIntegerField(default=0)
    result_bytes = models.BigIntegerField(default=0)
    result_offsite = models.CharField(max_length=8, blank=True)
    # The non-secret offsite location and the newest copy result (#403).
    offsite = models.JSONField(default=dict, blank=True)
    copy = models.JSONField(default=dict, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "identifier"], name="one_backup_observation_per_site"
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        state = "backed up" if self.enabled else "not backed up"
        return f"{state}: {self.identifier} in {self.snapshot}"
