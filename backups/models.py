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
