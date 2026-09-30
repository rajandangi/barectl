"""Database plans' typed review records (docs/databases.md).

Each is immutable and deleted with its plan; nothing here is written to the server.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models
from django.db.models.expressions import Combinable

from bootstrap.models import ConfigurationPlan, ImmutableRecord, PlanPreparation

if TYPE_CHECKING:
    from bootstrap.models import _Permissions


class DatabaseRequest(ImmutableRecord):
    """What the operator asked to prepare, stored with the queued preparation."""

    preparation = models.OneToOneField(
        PlanPreparation,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="database_request",
    )

    class Meta:
        # docs/databases.md#permissions: database plans have their own viewers, preparers and
        # appliers.
        default_permissions: ClassVar[Sequence[str]] = ()
        permissions: ClassVar[_Permissions] = [
            ("view_databaseplan", "Can view database plans"),
            ("prepare_databaseplan", "Can prepare database plans"),
            ("apply_databaseplan", "Can apply database plans"),
        ]

    @override
    def __str__(self) -> str:
        return f"Database request of {self.preparation}"


class PlanDriverPool(ImmutableRecord):
    """A PHP-FPM pool a driver plan's reload restarts, as preparation recognized it."""

    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="driver_pools"
    )
    position = models.PositiveSmallIntegerField()
    name = models.CharField(max_length=24)
    user = models.CharField(max_length=32)
    socket = models.CharField(max_length=100)
    # The distribution's own pool, rather than a site's.
    default = models.BooleanField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return f"Pool {self.name}"
