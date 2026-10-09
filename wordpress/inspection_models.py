"""A WordPress inspection's persisted records (docs/wordpress.md#inspecting-wordpress).

Each is immutable and deleted with its plan or run. The review rows hold public pins and
observed non-secret facts only; the result rows hold the validated, capped record the unit
published, never a command's raw output.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models
from django.db.models.expressions import Combinable

from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation

if TYPE_CHECKING:
    from bootstrap.models import _Permissions


class Operation(models.TextChoices):
    """The named diagnostics (docs/wordpress-native-design.md#named-wp-cli-operations)."""

    INSPECT = "inspect", "Inspect WordPress"
    CORE = "core", "Verify core checksums"
    PLUGINS = "plugins", "Verify repository plugin checksums"


class InspectionRequest(ImmutableRecord):
    """Which diagnostic an operator asked a review for, stored with the queued preparation.

    Its Meta defines the permission to run an inspection from a reviewed plan, which is
    separate from viewing or preparing plans, installing and every site, database or
    certificate permission (docs/wordpress.md#review-permissions).
    """

    preparation = models.OneToOneField(
        PlanPreparation,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="inspection_request",
    )
    identifier = models.CharField(max_length=24)
    operation = models.CharField(max_length=10, choices=Operation)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        permissions: ClassVar[_Permissions] = [
            ("inspect_wordpress", "Can run an explicit WordPress inspection from a reviewed plan"),
        ]

    @override
    def __str__(self) -> str:
        return f"WordPress inspection request for {self.identifier}"


class InspectionReview(ImmutableRecord):
    """The immutable inspection intent a review binds, as its apply run consumes it."""

    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=3)
    php_supply = models.CharField(max_length=10, default="ubuntu")
    site_revision = models.PositiveSmallIntegerField()
    site_user = models.CharField(max_length=32)
    uid = models.PositiveIntegerField()
    gid = models.PositiveIntegerField()
    canonical_name = models.CharField(max_length=46)
    url = models.CharField(max_length=60)
    operation = models.CharField(max_length=10, choices=Operation)
    # The authenticated WP-CLI the run executes.
    tool_version = models.CharField(max_length=20)
    tool_path = models.CharField(max_length=200)
    tool_sha256 = models.CharField(max_length=64)
    # The observed core release and where it stands against the qualified one.
    core_version = models.CharField(max_length=40)
    core_locale = models.CharField(max_length=10)
    core_qualified = models.BooleanField()
    configuration_sha256 = models.CharField(max_length=64)
    # What the run may execute or check, one "kind name" per line: the repository-slug
    # plugin directories, the must-use plugins and drop-ins that run with WordPress, and the
    # themes. These are the observed names the application state digest binds.
    targets = models.TextField(blank=True)
    # The native limits and the time budgets the body enforces.
    max_file_bytes = models.PositiveBigIntegerField()
    memory_max_bytes = models.PositiveBigIntegerField()
    runtime_limit_seconds = models.PositiveIntegerField()
    command_seconds = models.PositiveIntegerField()
    budget_seconds = models.PositiveIntegerField()
    # The reviewed native body the run executes (docs/adr/0006-use-native-bootstrap-execution.md).
    body_sha256 = models.CharField(max_length=64, blank=True)
    payload_bytes = models.PositiveIntegerField(null=True)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"WordPress {self.get_operation_display()} of {self.identifier}"

    def names(self, kind: str) -> list[str]:
        """The reviewed target names of one kind."""
        return [
            name
            for line in self.targets.splitlines()
            for found, _, name in [line.partition(" ")]
            if found == kind
        ]


class PlanWordpressInspection(InspectionReview):
    plan = models.OneToOneField(
        ConfigurationPlan,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="wordpress_inspection",
    )


class RunWordpressInspection(InspectionReview):
    """An apply run's copy of its plan's inspection review, kept with the run's audit."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="wordpress_inspection"
    )


class InspectionResult(ImmutableRecord):
    """What an inspection run published and Barectl retrieved and validated.

    Besides the run's execution outcome and its verification, this is the third axis: whether
    the bounded result record could be retrieved. It is written once, by the first
    verification of a succeeded run, and is application-reported data as of ``reported_at``,
    not a live-security assessment.
    """

    class State(models.TextChoices):
        AVAILABLE = "available", "Available"
        UNAVAILABLE = "unavailable", "Unavailable"

    class Integrity(models.TextChoices):
        MATCH = "match", "Matches the official checksums"
        MISMATCH = "mismatch", "Differs from the official checksums"
        UNAVAILABLE = "unavailable", "Could not be checked"

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="inspection_result"
    )
    operation = models.CharField(max_length=10, choices=Operation)
    state = models.CharField(max_length=12, choices=State)
    # Why the result is unavailable, from the fixed reason vocabulary.
    why = models.CharField(max_length=20, blank=True)
    retrieved_at = models.DateTimeField()
    # The server's clock when the record was made; empty when no record was retrieved.
    reported_at = models.DateTimeField(null=True)
    core_version = models.CharField(max_length=40, blank=True)
    core_installed = models.BooleanField(null=True)
    integrity = models.CharField(max_length=12, choices=Integrity, blank=True)
    integrity_why = models.CharField(max_length=20, blank=True)
    modified = models.PositiveIntegerField(default=0)
    missing = models.PositiveIntegerField(default=0)
    extra = models.PositiveIntegerField(default=0)
    # The first differing paths, one "modified|missing|extra path" per line.
    files = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Result of run {self.run_id}"


class InspectionItem(ImmutableRecord):
    """One inventory entry or one checked plugin of a result."""

    class Kind(models.TextChoices):
        PLUGIN = "plugin", "Plugin"
        MU_PLUGIN = "mu-plugin", "Must-use plugin"
        DROPIN = "dropin", "Drop-in"
        THEME = "theme", "Theme"

    result = models.ForeignKey(InspectionResult, on_delete=models.CASCADE, related_name="items")
    position = models.PositiveSmallIntegerField()
    kind = models.CharField(max_length=10, choices=Kind)
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=20, blank=True)
    version = models.CharField(max_length=40, blank=True)
    # A plugin verification's classification; empty for the inventory.
    verdict = models.CharField(max_length=12, choices=InspectionResult.Integrity, blank=True)
    why = models.CharField(max_length=20, blank=True)
    modified = models.PositiveIntegerField(default=0)
    added = models.PositiveIntegerField(default=0)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return f"{self.kind} {self.name}"
