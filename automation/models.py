"""Typed snapshot rows for a site's background work (ADR 0003, Phase C #357).

A fresh controller reconstructs the setting and its last result from these rows alone; no
controller-side history decides what was on.
"""

from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models
from django.db.models.expressions import Combinable


class AutomationObservation(models.Model):
    """One role of one site, as native evidence and the pure projection recorded it."""

    snapshot = models.ForeignKey(
        "discovery.DiscoverySnapshot", on_delete=models.CASCADE, related_name="automation"
    )
    identifier = models.CharField(max_length=24)
    role = models.CharField(max_length=24)
    status = models.CharField(max_length=20)
    problem = models.TextField(blank=True)
    duplicate = models.TextField(blank=True)
    disable_wp_cron = models.CharField(max_length=8, blank=True)
    installed = models.BooleanField(default=False)
    timer_active = models.BooleanField(default=False)
    timer_enabled = models.BooleanField(default=False)
    service_active = models.BooleanField(default=False)
    masked = models.BooleanField(default=False)
    result = models.CharField(max_length=20, blank=True)
    exec_status = models.PositiveIntegerField(default=0)
    last_start_us = models.BigIntegerField(default=0)
    last_exit_us = models.BigIntegerField(default=0)
    last_trigger_us = models.BigIntegerField(default=0)
    next_elapse_us = models.BigIntegerField(default=0)
    slice_populated = models.BooleanField(default=False)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "identifier", "role"],
                name="unique_automation_per_snapshot",
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.role} of {self.identifier} in {self.snapshot}"


class WorkerObservation(models.Model):
    """One site's queue workers, as native evidence and the pure projection recorded them."""

    snapshot = models.ForeignKey(
        "discovery.DiscoverySnapshot", on_delete=models.CASCADE, related_name="workers"
    )
    identifier = models.CharField(max_length=24)
    status = models.CharField(max_length=24)
    queues = models.TextField(blank=True)
    processes = models.PositiveSmallIntegerField(default=0)
    timeout = models.PositiveIntegerField(default=0)
    active_processes = models.PositiveSmallIntegerField(default=0)
    installed = models.BooleanField(default=False)
    enabled = models.BooleanField(default=False)
    masked = models.BooleanField(default=False)
    start_limited = models.BooleanField(default=False)
    slice_populated = models.BooleanField(default=False)
    result = models.CharField(max_length=24, blank=True)
    exec_status = models.PositiveIntegerField(default=0)
    last_start_us = models.BigIntegerField(default=0)
    last_exit_us = models.BigIntegerField(default=0)
    nrestarts = models.PositiveIntegerField(default=0)
    duplicate = models.TextField(blank=True)
    problem = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "identifier"],
                name="unique_worker_per_snapshot",
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"queue workers of {self.identifier} in {self.snapshot}"
