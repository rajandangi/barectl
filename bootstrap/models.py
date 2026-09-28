"""Plan preparation and the immutable configuration plans it records.

A plan preparation is the read-only remote operation that inspects a server for one
bootstrap profile or maintenance action. When it finishes, it records one configuration
plan: the eligibility decision, the exact proposed effects, and fingerprints of the
native evidence they were derived from. Plans are local records of this installation;
nothing is written to the server. Plans never change once saved: a changed server needs a
new preparation and review.
"""

from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, ClassVar, NoReturn, override

from django.conf import settings
from django.db import models
from django.db.models import F, Q
from django.db.models.base import ModelBase
from django.db.models.expressions import Combinable

from operations.models import RemoteOperation

if TYPE_CHECKING:
    from django.utils.functional import _StrPromise

    # Django's type for Meta.permissions, declared exactly so the override is not narrower.
    type _Permissions = (
        list[tuple[str, str | _StrPromise]] | tuple[tuple[str, str | _StrPromise], ...]
    )

# The admission deadline is this long after collection on the server's monotonic clock.
ADMISSION_CENTISECONDS = 15 * 60 * 100


class Action(models.TextChoices):
    """What an operator can prepare: a bootstrap profile or a maintenance action."""

    NGINX = "nginx", "Nginx profile"
    PHP = "php8.3", "PHP 8.3 profile (FPM and CLI)"
    METADATA_REFRESH = "metadata_refresh", "Package metadata refresh"


class Privilege(models.TextChoices):
    """The privilege the SSH user has for applying a plan, as preparation verified it."""

    ROOT = "root", "Root"
    SUDO = "sudo", "Noninteractive sudo"
    UNAVAILABLE = "unavailable", "Unavailable"


class ImmutableRecord(models.Model):
    """A plan record, which is created once and never updated."""

    class Meta:
        abstract = True

    @override
    def save(
        self,
        *,
        force_insert: bool | tuple[ModelBase, ...] = False,
        force_update: bool = False,
        using: str | None = None,
        update_fields: Iterable[str] | None = None,
    ) -> None:
        if not self._state.adding or force_update or update_fields is not None:
            _refuse_change()
        super().save(force_insert=True, using=using)


def _refuse_change() -> NoReturn:
    raise ValueError("Configuration plans are immutable; prepare a new plan instead.")


class PlanPreparation(RemoteOperation):
    """The plan preparation kind of remote operation: a read-only inspection for a plan."""

    KIND: ClassVar[str] = RemoteOperation.Kind.PLAN_PREPARATION

    action = models.CharField(max_length=20, choices=Action)
    # The account that asked. The worker checks it is still active and allowed before it
    # connects; a deleted account leaves the preparation without one.
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )

    class Meta:
        # Access to preparations and their plans is granted on ConfigurationPlan.
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} preparation of {self.get_action_display()}"


class ConfigurationPlan(ImmutableRecord):
    """One immutable plan revision, bound to the native evidence it was prepared from.

    A plan records the verified host key and boot, a server-monotonic admission deadline
    fifteen minutes after collection, fingerprints of the evidence, and for a package
    profile its exact root versions and complete dependency transitions. A refused plan
    records why instead; it is still a review, never an authorization.
    """

    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.CASCADE, primary_key=True, related_name="plan"
    )
    action = models.CharField(max_length=20, choices=Action)
    # The revision of the profile or action definition the plan was reviewed against.
    profile_revision = models.PositiveSmallIntegerField()
    # The operator intent, in the pages' wording.
    intent = models.CharField(max_length=200)
    eligible = models.BooleanField()
    # Eligible with nothing to do: the profile is already satisfied and healthy.
    no_changes = models.BooleanField(default=False)
    ssh_alias = models.CharField("SSH alias", max_length=253)
    host_key = models.CharField(max_length=200)
    # /proc/sys/kernel/random/boot_id at collection; empty when it could not be read.
    boot_id = models.CharField(max_length=36, blank=True)
    # /proc/uptime at the start of collection, in hundredths of a second, and the deadline
    # on the same clock after which the plan can no longer be admitted.
    uptime_centiseconds = models.BigIntegerField(null=True)
    admission_deadline_centiseconds = models.BigIntegerField(null=True)
    # The controller's clock when collection started, and its estimate of the deadline.
    collected_at = models.DateTimeField()
    admission_expires_at = models.DateTimeField()
    os_name = models.CharField(max_length=200, blank=True)
    architecture = models.CharField(max_length=20, blank=True)
    apt_version = models.CharField(max_length=100, blank=True)
    dpkg_version = models.CharField(max_length=100, blank=True)
    systemd_version = models.CharField(max_length=100, blank=True)
    privilege = models.CharField(max_length=12, choices=Privilege)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ("view",)
        permissions: ClassVar[_Permissions] = [
            ("prepare_configurationplan", "Can prepare configuration plans"),
            ("apply_configurationplan", "Can apply reviewed configuration plans"),
            ("clear_native_results", "Can clear terminal native execution results"),
        ]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.CheckConstraint(
                condition=Q(uptime_centiseconds__isnull=True, admission_deadline_centiseconds=None)
                | Q(
                    admission_deadline_centiseconds=F("uptime_centiseconds")
                    + ADMISSION_CENTISECONDS
                ),
                name="plan_admission_deadline_fifteen_minutes",
            ),
            # Only a plan bound to its boot and monotonic clock can be eligible.
            models.CheckConstraint(
                condition=Q(eligible=False)
                | (~Q(boot_id="") & Q(uptime_centiseconds__isnull=False)),
                name="eligible_plan_has_boot_and_deadline",
            ),
            models.CheckConstraint(
                condition=Q(eligible=False) | ~Q(privilege="unavailable"),
                name="eligible_plan_has_privilege",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Plan {self.pk}: {self.get_action_display()}"


class PlanRootPackage(ImmutableRecord):
    """A package the profile asks for, at the exact version the plan reviewed."""

    plan = models.ForeignKey(ConfigurationPlan, on_delete=models.CASCADE, related_name="roots")
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=100)
    # Already installed at this version, so the plan does not install it.
    installed = models.BooleanField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.name} {self.version}"


class PackageTransition(ImmutableRecord):
    """One package action from APT's simulation of the profile's installation."""

    class Step(models.TextChoices):
        INSTALL = "install", "Install"
        CONFIGURE = "configure", "Configure"

    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="transitions"
    )
    # The simulation's order.
    position = models.PositiveSmallIntegerField()
    step = models.CharField(max_length=10, choices=Step)
    package = models.CharField(max_length=100)
    architecture = models.CharField(max_length=20)
    version = models.CharField(max_length=100)
    # The archives offering the version, such as "Ubuntu:24.04/noble-updates", one per line.
    origins = models.TextField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["plan", "position"], name="unique_transition_position_per_plan"
            )
        ]

    @override
    def __str__(self) -> str:
        return f"{self.get_step_display()} {self.package} {self.version}"


class PlanEffect(ImmutableRecord):
    """One effect the plan would have on the server, as the review explains it."""

    class Kind(models.TextChoices):
        NO_CHANGES = "no_changes", "No changes"
        PACKAGES = "packages", "Package installation"
        MAINTAINER_START = "maintainer_start", "Package maintainer service start"
        HTTP_LISTENER = "http_listener", "Default HTTP listener"
        LOCAL_SOCKET = "local_socket", "Local socket"
        SERVICE_ENABLE = "service_enable", "Service enablement"
        SERVICE_START = "service_start", "Service start"
        NEEDRESTART = "needrestart", "Native restart policy"
        INDEX_UPDATE = "index_update", "Package index update"
        UPDATE_HOOKS = "update_hooks", "APT hooks"
        INVALIDATES_PLANS = "invalidates_plans", "Earlier plans invalidated"
        NO_ROLLBACK = "no_rollback", "No rollback"

    plan = models.ForeignKey(ConfigurationPlan, on_delete=models.CASCADE, related_name="effects")
    position = models.PositiveSmallIntegerField()
    kind = models.CharField(max_length=20, choices=Kind)
    text = models.TextField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.get_kind_display()


class PlanPostcondition(ImmutableRecord):
    """What must hold on the server after a successful apply of the plan."""

    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="postconditions"
    )
    position = models.PositiveSmallIntegerField()
    text = models.TextField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.text


class PlanRefusal(ImmutableRecord):
    """One reason the plan cannot be applied, with what the operator can do about it."""

    class Reason(models.TextChoices):
        UNSUPPORTED_PLATFORM = "unsupported_platform", "Unsupported platform"
        PRIVILEGE = "privilege", "Privilege unavailable"
        PACKAGE_HEALTH = "package_health", "Package database needs attention"
        HELD_PACKAGE = "held_package", "Held package"
        APT_HOOK = "apt_hook", "Unknown APT hook"
        APT_CONFIGURATION = "apt_configuration", "Unsupported APT configuration"
        PACKAGE_SOURCE = "package_source", "Unqualified package source"
        PACKAGE_METADATA = "package_metadata", "Package indexes unavailable"
        INSTALLED_PACKAGE_CHANGE = "installed_package_change", "Installed package would change"
        CUSTOMIZED = "customized", "Customized configuration"
        LEFTOVER = "leftover", "Leftover configuration"
        SERVICE_UNIT = "service_unit", "Service unit needs attention"
        LISTENER = "listener", "Conflicting listener"
        SIMULATION = "simulation", "Package simulation refused"
        INCOMPLETE = "incomplete", "Incomplete evidence"

    plan = models.ForeignKey(ConfigurationPlan, on_delete=models.CASCADE, related_name="refusals")
    position = models.PositiveSmallIntegerField()
    reason = models.CharField(max_length=30, choices=Reason)
    text = models.TextField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.get_reason_display()


class PlanEvidence(ImmutableRecord):
    """A fingerprint of one kind of native evidence the plan was derived from.

    Only a SHA-256 digest of normalized evidence and a short summary are kept, never the
    configuration, output or credentials themselves. A later check compares digests.
    """

    class Kind(models.TextChoices):
        PLATFORM = "platform", "Platform and boot"
        PRIVILEGE = "privilege", "Privilege"
        APT_CONFIGURATION = "apt_configuration", "Effective APT configuration"
        APT_HOOKS = "apt_hooks", "APT hooks"
        APT_SOURCES = "apt_sources", "APT sources"
        APT_PREFERENCES = "apt_preferences", "APT preferences"
        PACKAGE_INDEXES = "package_indexes", "Package indexes"
        DPKG_STATUS = "dpkg_status", "Relevant package states"
        PACKAGE_HOLDS = "package_holds", "Package holds"
        AUTO_MARKS = "auto_marks", "Automatic installation marks"
        SIMULATION = "simulation", "APT simulation"
        WEB_CONFIGURATION = "web_configuration", "Web-stack configuration"
        SERVICE_UNITS = "service_units", "Service units"
        LISTENERS = "listeners", "Listeners"

    plan = models.ForeignKey(ConfigurationPlan, on_delete=models.CASCADE, related_name="evidence")
    kind = models.CharField(max_length=20, choices=Kind)
    # SHA-256 of the normalized evidence, in hexadecimal.
    fingerprint = models.CharField(max_length=64)
    summary = models.CharField(max_length=300)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(fields=["plan", "kind"], name="unique_evidence_kind_per_plan")
        ]

    @override
    def __str__(self) -> str:
        return self.get_kind_display()
