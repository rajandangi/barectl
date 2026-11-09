"""Typed Jobs observations attached to a discovery snapshot (Phase E #285).

Discovery stores what the server itself says about Barectl's own change runs: the units
systemd still retains and the journal result lines Phase A's engine writes. The rows are a
bounded observation, never authority: the next check replaces them, and a failed check
keeps the previous snapshot (docs/adr/0003-store-discovery-snapshots-in-typed-columns.md).
"""

from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models
from django.db.models.expressions import Combinable

from discovery.models import DiscoverySnapshot


class Coverage(models.TextChoices):
    """How much of a provider's native evidence the last read could establish."""

    COMPLETE = "complete", "Complete"
    NO_EVIDENCE = "no_evidence", "No evidence"
    ACCESS_DENIED = "access_denied", "Access denied"
    UNREADABLE = "unreadable", "Unreadable"
    READ_FAILED = "read_failed", "Read failed"
    TRUNCATED = "truncated", "Truncated"


class JobCoverage(models.Model):
    """One provider's coverage in one snapshot."""

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="job_coverage"
    )
    provider = models.CharField(max_length=32)
    state = models.CharField(max_length=20, choices=Coverage)
    warning = models.TextField(blank=True)
    # The oldest journal time the server still holds, when the read established one.
    oldest_at = models.DateTimeField(null=True, blank=True)
    source = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "provider"], name="one_job_coverage_per_provider"
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["provider"]

    @override
    def __str__(self) -> str:
        return f"{self.provider}: {self.get_state_display()}"


class JobObservation(models.Model):
    """One observed Barectl change run, from its unit or its journal result line.

    ``result_class`` is empty when no readable result line was available: the presentation
    words that as Could not confirm or an unreadable result line, never as success or
    failure. A result-line time with no class marks a line Barectl could not read. Only the
    unit, invocation, the two timestamps and the parsed outcome are kept; journal messages
    never are.
    """

    snapshot = models.ForeignKey(DiscoverySnapshot, on_delete=models.CASCADE, related_name="jobs")
    provider = models.CharField(max_length=32)
    unit = models.CharField(max_length=80)
    invocation_id = models.CharField(max_length=32, blank=True)
    kind_slug = models.CharField(max_length=40, blank=True)
    sites = models.JSONField(default=list)
    result_class = models.CharField(max_length=20, blank=True)
    reason = models.CharField(max_length=40, blank=True)
    # The native contract version that wrote the result line; zero before the field existed.
    contract = models.PositiveSmallIntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    running = models.BooleanField(default=False)
    active_state = models.CharField(max_length=30, blank=True)
    sub_state = models.CharField(max_length=30, blank=True)
    exec_main_status = models.PositiveSmallIntegerField(null=True, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "provider", "unit", "invocation_id"],
                name="one_job_row_per_run",
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.provider}: {self.unit}"
