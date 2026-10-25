"""The object cache's stored observation and its on-demand reading (Phase C #392).

A discovery snapshot keeps one typed row per site (ADR 0003). An on-demand reading is a
read operation through the worker and ``RemoteShell``; its numbers live only on that
request row and are replaced by the next reading, so no cache value or metric becomes a
second source of truth.
"""

from collections.abc import Sequence
from typing import ClassVar, override

from django.conf import settings
from django.db import models

from operations.models import RemoteOperation
from servers.models import Server


class CacheState(models.TextChoices):
    OFF = "off", "Off"
    ON = "on", "On"
    PARTIAL = "partial", "Partly on"
    UNSUPPORTED = "unsupported", "Outside supported settings"


class CacheObservation(models.Model):
    """One site's cache instance and application wiring, from one discovery snapshot."""

    snapshot = models.ForeignKey(
        "discovery.DiscoverySnapshot", on_delete=models.CASCADE, related_name="cache"
    )
    identifier = models.CharField(max_length=24)
    state = models.CharField(max_length=14, choices=CacheState)
    memory_mib = models.PositiveIntegerField(null=True, blank=True)
    problem = models.TextField(blank=True)
    plugin_version = models.CharField(max_length=40, blank=True)
    client = models.CharField(max_length=16, blank=True)
    unit_state = models.CharField(max_length=20, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "identifier"], name="one_cache_observation_per_site"
            )
        ]

    @override
    def __str__(self) -> str:
        return f"{self.state} object cache of {self.identifier}"


class CacheReading(RemoteOperation):
    """A read of one site's cache metrics, kept only on this request."""

    KIND: ClassVar[str] = RemoteOperation.Kind.CACHE_READING
    identifier = models.CharField(max_length=24)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    reading = models.JSONField(default=dict)
    reading_at = models.DateTimeField(null=True, blank=True)
    # A reading always has a server; the base constraint allows only finished apply runs
    # to outlive one.
    server: Server  # type: ignore[mutable-override]

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} object cache reading of {self.identifier}"
