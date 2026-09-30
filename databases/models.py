"""Database plans' typed review records (docs/databases.md).

Each is immutable and deleted with its plan; nothing here is written to the server.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models
from django.db.models.expressions import Combinable

from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation
from discovery.models import DatabaseEngine, ObservationOutcome

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
    # Empty for a driver or an inspection, which name no site.
    identifier = models.CharField(max_length=24, blank=True)
    engine = models.CharField(max_length=12, choices=DatabaseEngine, blank=True)

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


class BindingRecord(ImmutableRecord):
    """What a binding plan creates, as its review and its run's audit keep it."""

    identifier = models.CharField(max_length=24)
    engine = models.CharField(max_length=12, choices=DatabaseEngine)
    php_version = models.CharField(max_length=10)
    site_user = models.CharField(max_length=32)
    uid = models.PositiveIntegerField()
    gid = models.PositiveIntegerField()
    principal = models.CharField(max_length=32)
    database = models.CharField(max_length=32)
    authentication = models.CharField(max_length=100)
    character_set = models.CharField(max_length=40)
    collation = models.CharField(max_length=100)
    engine_version = models.CharField(max_length=100)
    driver_version = models.CharField(max_length=100)
    # Whether the other engine is installed, so the catalog read covers it too.
    other_engine = models.BooleanField()
    # The temporary probe's name part, 32 hexadecimal digits, and its complete bytes.
    probe_token = models.CharField(max_length=32)
    probe_path = models.CharField(max_length=100)
    probe_content = models.TextField()
    probe_sha256 = models.CharField(max_length=64)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"{self.get_engine_display()} binding of {self.identifier}"


class StatementRecord(ImmutableRecord):
    position = models.PositiveSmallIntegerField()
    step = models.CharField(max_length=12)
    # The database a PostgreSQL statement runs in; empty for MariaDB.
    database = models.CharField(max_length=32, blank=True)
    text = models.TextField()

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.text


class PlanDatabaseBinding(BindingRecord):
    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="binding"
    )
    # The size of the payload built at preparation, which must fit one submission.
    payload_bytes = models.PositiveIntegerField(null=True)


class PlanDatabaseStatement(StatementRecord):
    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="binding_statements"
    )


# An apply run's copy of its plan's binding, kept with the run's audit after the plan is
# deleted with the server's registration.


class RunDatabaseBinding(BindingRecord):
    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="binding"
    )


class RunDatabaseStatement(StatementRecord):
    run = models.ForeignKey(ApplyRun, on_delete=models.CASCADE, related_name="binding_statements")


class DatabaseRunResult(ImmutableRecord):
    """What verification read after a successful run; never a secret."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="binding_result"
    )
    principal = models.CharField(max_length=100, blank=True)
    authentication = models.CharField(max_length=100, blank=True)
    privileges = models.TextField(blank=True)
    character_set = models.CharField(max_length=40, blank=True)
    collation = models.CharField(max_length=100, blank=True)
    probe_absent = models.BooleanField()
    # Each difference from the reviewed binding, one per line; empty when none.
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Verification of run {self.run_id}"


class PlanCatalogObservation(ImmutableRecord):
    """docs/databases.md#privileged-inspection: one site's binding as an inspection read
    it. Never merged into discovery or used as its fallback."""

    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="catalog_observations"
    )
    position = models.PositiveSmallIntegerField()
    identifier = models.CharField(max_length=24)
    engine = models.CharField(max_length=12, choices=DatabaseEngine, blank=True)
    status = models.CharField(max_length=12, choices=ObservationOutcome)
    conforms = models.BooleanField()
    principal = models.CharField(max_length=100, blank=True)
    database = models.CharField(max_length=100, blank=True)
    authentication = models.CharField(max_length=200, blank=True)
    privileges = models.TextField(blank=True)
    character_set = models.CharField(max_length=40, blank=True)
    collation = models.CharField(max_length=100, blank=True)
    owner = models.CharField(max_length=100, blank=True)
    warning = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return f"Catalog of {self.identifier}"
