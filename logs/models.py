"""A log read is a read-only remote operation with a temporary page (Phase C #389)."""

from collections.abc import Sequence
from datetime import timedelta
from typing import ClassVar, override

from django.conf import settings
from django.db import models

from operations.models import RemoteOperation

# docs/logs.md#pages: a page lives only on its request row and never beyond this.
PAGE_LIFETIME = timedelta(hours=24)


class LogOutcome(models.TextChoices):
    PENDING = "pending", "Not read yet"
    OBSERVED = "observed", "Read"
    MISSING = "missing", "Missing"
    EMPTY = "empty", "Empty"
    UNREADABLE = "unreadable", "Unreadable"
    ROTATED = "rotated", "Rotated away"


class LogRead(RemoteOperation):
    """One explicit request to read one log of one site.

    The page is stored only here, is removed after ``PAGE_LIFETIME`` or at the next read of
    the same log, and is never copied to a snapshot or a change record.
    """

    KIND: ClassVar[str] = RemoteOperation.Kind.LOG_READ

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    identifier = models.CharField(max_length=24)
    source = models.CharField(max_length=20)
    # The plain search term and the time range the operator chose; values are never secrets
    # and every control is bounded before the request is queued.
    term = models.CharField(max_length=100, blank=True)
    since = models.DateTimeField(null=True, blank=True)
    until = models.DateTimeField(null=True, blank=True)
    # An opaque continuation for older lines: file identity plus byte offset.
    cursor = models.CharField(max_length=200, blank=True)
    outcome = models.CharField(max_length=12, choices=LogOutcome, default=LogOutcome.PENDING)
    page = models.JSONField(default=dict)
    page_expires_at = models.DateTimeField(null=True, blank=True)
    collected_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} log read of {self.identifier}/{self.source}"
