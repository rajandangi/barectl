"""A WordPress maintenance action's persisted records (docs/wordpress.md#maintaining-wordpress).

Each is immutable and deleted with its plan or run. The review rows are the inspection's
application binding (``InspectionReview``) with the maintenance operation; the result row holds
the validated, capped record the unit published, never a command's raw output.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models

from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation

from .inspection_models import InspectionReview

if TYPE_CHECKING:
    from bootstrap.models import _Permissions


class Operation(models.TextChoices):
    """The named maintenance actions (docs/wordpress-native-design.md#named-wp-cli-operations)."""

    REWRITE = "rewrite", "Flush rewrite rules"
    CACHE = "cache", "Flush object cache"


class MaintenanceRequest(ImmutableRecord):
    """Which maintenance action an operator asked a review for, stored with the queued
    preparation.

    Its Meta defines the permission to run a maintenance action from a reviewed plan, which is
    separate from viewing or preparing plans, installing, inspecting and every site, database
    or certificate permission (docs/wordpress.md#review-permissions).
    """

    preparation = models.OneToOneField(
        PlanPreparation,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="maintenance_request",
    )
    identifier = models.CharField(max_length=24)
    operation = models.CharField(max_length=10, choices=Operation)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        permissions: ClassVar[_Permissions] = [
            ("maintain_wordpress", "Can run WordPress maintenance from a reviewed plan"),
        ]

    @override
    def __str__(self) -> str:
        return f"WordPress maintenance request for {self.identifier}"


class MaintenanceReview(InspectionReview):
    """The immutable maintenance intent a review binds, as its apply run consumes it."""

    operation = models.CharField(max_length=10, choices=Operation)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"WordPress {self.get_operation_display()} of {self.identifier}"


class PlanWordpressMaintenance(MaintenanceReview):
    plan = models.OneToOneField(
        ConfigurationPlan,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="wordpress_maintenance",
    )


class RunWordpressMaintenance(MaintenanceReview):
    """An apply run's copy of its plan's maintenance review, kept with the run's audit."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="wordpress_maintenance"
    )


class MaintenanceResult(ImmutableRecord):
    """What a maintenance run published and Barectl retrieved and validated.

    Beside the run's execution outcome and its verification, this is the third axis: whether
    the bounded result record could be retrieved. It is written once, by the first verification
    of a succeeded run, and is application-reported data as of ``reported_at``.
    """

    class State(models.TextChoices):
        AVAILABLE = "available", "Available"
        UNAVAILABLE = "unavailable", "Unavailable"

    class Rules(models.TextChoices):
        STORED = "stored", "Rewrite rules are stored"
        EMPTY = "empty", "No rewrite rules are stored"

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="maintenance_result"
    )
    operation = models.CharField(max_length=10, choices=Operation)
    state = models.CharField(max_length=12, choices=State)
    why = models.CharField(max_length=20, blank=True)
    retrieved_at = models.DateTimeField()
    reported_at = models.DateTimeField(null=True)
    # A rewrite flush's stored-rules observation; empty for every other action.
    rules = models.CharField(max_length=10, choices=Rules, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Maintenance result of run {self.run_id}"
