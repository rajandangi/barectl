"""Native PHP selection collected with source-tool admission (docs/site-creation.md)."""

from collections.abc import Sequence
from typing import ClassVar

from django.db import models

from .models import ImmutableRecord


class SourceToolsSelection(ImmutableRecord):
    plan = models.OneToOneField(
        "bootstrap.ConfigurationPlan",
        on_delete=models.CASCADE,
        related_name="source_tools_selection",
    )
    supply = models.CharField(max_length=6)
    installed = models.BooleanField()
    default_branch = models.CharField(max_length=3, blank=True)
    fingerprint = models.CharField(max_length=64)

    class Meta:
        app_label = "bootstrap"
        default_permissions: ClassVar[Sequence[str]] = ()
