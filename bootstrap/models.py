"""docs/adr/0005-review-exact-bootstrap-transitions.md"""

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

ADMISSION_CENTISECONDS = 15 * 60 * 100


class Action(models.TextChoices):
    NGINX = "nginx", "Nginx profile"
    PHP = "php", "PHP profile (FPM and CLI)"
    MARIADB = "mariadb", "MariaDB profile"
    POSTGRESQL = "postgresql", "PostgreSQL profile"
    METADATA_REFRESH = "metadata_refresh", "Package metadata refresh"
    CLEAR_RESULTS = "clear_results", "Clear finished bootstrap runs"
    # docs/ssh-connections.md#site-preparation
    SITE_HTTP = "site_http", "HTTP PHP site"
    # docs/databases.md
    PHP_MYSQL = "php_mysql", "PHP MariaDB driver"
    PHP_PGSQL = "php_pgsql", "PHP PostgreSQL driver"
    DATABASE_MARIADB = "database_mariadb", "MariaDB site database"
    DATABASE_POSTGRESQL = "database_postgresql", "PostgreSQL site database"
    DATABASE_INSPECTION = "database_inspection", "Privileged database inspection"


class Privilege(models.TextChoices):
    ROOT = "root", "Root"
    SUDO = "sudo", "Noninteractive sudo"
    UNAVAILABLE = "unavailable", "Unavailable"


class ImmutableRecord(models.Model):
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
    KIND: ClassVar[str] = RemoteOperation.Kind.PLAN_PREPARATION

    action = models.CharField(max_length=20, choices=Action)
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
    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.CASCADE, primary_key=True, related_name="plan"
    )
    action = models.CharField(max_length=20, choices=Action)
    profile_revision = models.PositiveSmallIntegerField()
    intent = models.CharField(max_length=200)
    eligible = models.BooleanField()
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
    # The supported Ubuntu release whose policy and profiles the plan was reviewed against,
    # such as "26.04" (bootstrap.releases); empty when the platform is not supported.
    release = models.CharField(max_length=5, blank=True)
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
            models.CheckConstraint(
                condition=Q(eligible=False)
                | (~Q(boot_id="") & Q(uptime_centiseconds__isnull=False)),
                name="eligible_plan_has_boot_and_deadline",
            ),
            models.CheckConstraint(
                condition=Q(eligible=False) | ~Q(privilege="unavailable"),
                name="eligible_plan_has_privilege",
            ),
            models.CheckConstraint(
                condition=Q(eligible=False) | ~Q(release=""),
                name="eligible_plan_has_release",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Plan {self.pk}: {self.get_action_display()}"


class PlanRootPackage(ImmutableRecord):
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
    # The archives offering the version, such as "Ubuntu:26.04/resolute-updates", one per line.
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
    class Kind(models.TextChoices):
        NO_CHANGES = "no_changes", "No changes"
        PACKAGES = "packages", "Package installation"
        PACKAGE_GUARD = "package_guard", "Transaction guard"
        MAINTAINER_START = "maintainer_start", "Package maintainer service start"
        HTTP_LISTENER = "http_listener", "Default HTTP listener"
        LOCAL_SOCKET = "local_socket", "Local socket"
        DATABASE_LISTENERS = "database_listeners", "Local database listeners"
        DATA_DIRECTORY = "data_directory", "Data directory initialization"
        SERVICE_ENABLE = "service_enable", "Service enablement"
        SERVICE_START = "service_start", "Service start"
        NEEDRESTART = "needrestart", "Native restart policy"
        INDEX_UPDATE = "index_update", "Package index update"
        THIRD_PARTY_SOURCES = "third_party_sources", "Third-party package sources"
        UPDATE_HOOKS = "update_hooks", "APT hooks"
        INVALIDATES_PLANS = "invalidates_plans", "Earlier plans invalidated"
        NO_ROLLBACK = "no_rollback", "No rollback"
        CLEAR_UNITS = "clear_units", "Finished runs cleared"
        NATIVE_EVIDENCE = "native_evidence", "Native evidence removed"
        KEPT_UNITS = "kept_units", "Units left in place"
        # docs/site-conventions.md
        SITE_ACCOUNT = "site_account", "Site user and group"
        SITE_DIRECTORIES = "site_directories", "Site directories"
        SITE_FILES = "site_files", "Configuration and content files"
        SERVICE_RELOAD = "service_reload", "Service reloads"
        HTTP_ROUTING = "http_routing", "HTTP routing"
        ACCEPTANCE_PROBE = "acceptance_probe", "Temporary serving probe"
        ISOLATION_LIMITS = "isolation_limits", "Isolation limits"
        # docs/databases.md
        DRIVER_MODULES = "driver_modules", "PHP driver modules"
        DATABASE_PRINCIPAL = "database_principal", "Database principal"
        DATABASE_CREATION = "database_creation", "Database"
        DATABASE_PRIVILEGES = "database_privileges", "Database privileges"
        CONNECTION = "connection", "Connection instructions"
        CATALOG_INSPECTION = "catalog_inspection", "Read-only catalog inspection"

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
        UNSUPPORTED_VERSION = "unsupported_version", "Unsupported release installed"
        CONFLICT = "conflict", "Conflicting installation"
        ADMINISTRATION = "administration", "Administrative access not established"
        SIMULATION = "simulation", "Package simulation refused"
        INCOMPLETE = "incomplete", "Incomplete evidence"
        # docs/site-conventions.md
        COLLISION = "collision", "Existing resource"
        UNSUPPORTED_LAYOUT = "unsupported_layout", "Unsupported configuration layout"
        PARTIAL_SITE = "partial_site", "Incomplete site"
        PREREQUISITE = "prerequisite", "Prerequisite missing"
        PAYLOAD_TOO_LARGE = "payload_too_large", "Too large to submit"
        # docs/databases.md#database-bindings
        PARTIAL_BINDING = "partial_binding", "Incomplete database binding"
        EXISTING_BINDING = "existing_binding", "Existing database binding"

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
    """docs/v0.2.md#review-and-package-admission"""

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
        ADMINISTRATION = "administration", "Administrative access"
        DATA_PATHS = "data_paths", "Data directories and option files"
        # docs/adr/0006-use-native-bootstrap-execution.md#payload
        APT_REVALIDATION = "apt_revalidation", "APT evidence rechecked before applying"
        RETAINED_UNITS = "retained_units", "Retained bootstrap units"
        # docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md
        PACKAGE_REVALIDATION = (
            "package_revalidation",
            "Package and service evidence rechecked before applying",
        )
        # docs/ssh-connections.md#site-preparation
        SITE_REVALIDATION = "site_revalidation", "Site evidence rechecked before applying"
        NGINX_CLOSURE = "nginx_closure", "Nginx configuration"
        FPM_CLOSURE = "fpm_closure", "PHP-FPM configuration"
        ACCOUNTS = "accounts", "Accounts and groups"
        ALLOCATION = "allocation", "Account allocation policy"
        SITE_PATHS = "site_paths", "Site paths and ancestors"
        # docs/databases.md#database-bindings
        CATALOG = "catalog", "Database catalog"
        CATALOG_REVALIDATION = (
            "catalog_revalidation",
            "Database catalog rechecked before and during applying",
        )
        CATALOG_AFTER = "catalog_after", "Database catalog after applying"
        DRIVER = "driver", "PHP driver rechecked before applying"

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


class Execution(models.TextChoices):
    """docs/adr/0006-use-native-bootstrap-execution.md#inspection-and-outcomes"""

    NOT_SUBMITTED = "not_submitted", "Not submitted"
    SUBMITTED = "submitted", "Submitted; not yet confirmed on the server"
    NOT_FOUND = "not_found", "No native record found"
    RUNNING = "running", "Running on the server"
    SUCCEEDED = "succeeded", "Completed successfully"
    LOCK_CONFLICT = "lock_conflict", "Refused: another change holds the mutation lock"
    UNSAFE_LOCK = "unsafe_lock", "Refused: the lock directory is not safe"
    BOOT_CHANGED = "boot_changed", "Refused: the server restarted after review"
    EXPIRED = "expired", "Refused: the admission deadline had passed"
    OTHER_RUN_ACTIVE = "other_run_active", "Refused: another bootstrap run still has processes"
    DRIFT = "drift", "Refused: the reviewed evidence changed"
    RENEWAL_ACTIVE = (
        "renewal_active",
        "Refused: scheduled certificate renewal still has processes",
    )
    PACKAGE_MANAGER_BUSY = "package_manager_busy", "Refused: the package manager is busy"
    CAPACITY = "capacity", "Refused: too many finished runs are retained"
    TRANSACTION_REFUSED = (
        "transaction_refused",
        "Refused: APT's actual transaction differed from the reviewed one",
    )
    # docs/adr/0012-publish-site-files-without-replacing-them.md
    ACCOUNT_BUSY = "account_busy", "Refused: the account tool could not change the accounts"
    # docs/databases.md#recovering-a-partial-binding
    DRIVER_UNAVAILABLE = (
        "driver_unavailable",
        "Refused: the site's pool does not run as reviewed with the driver",
    )
    PRINCIPAL_CONFLICT = "principal_conflict", "Refused: the principal already existed"
    STATEMENT_REFUSED = "statement_refused", "Refused: the engine rejected the first statement"
    PARTIAL = "partial", "Stopped after changing the server: partly applied"
    FAILED = "failed", "Failed"
    INSTALL_NOT_STARTED = (
        "install_not_started",
        "Failed before dpkg changed any package",
    )
    INSTALL_FAILED = "install_failed", "Failed after dpkg changed packages"
    SERVICE_FAILED = "service_failed", "Failed to enable or start the service"
    VALIDATION_FAILED = (
        "validation_failed",
        "Changed, but the configuration syntax check failed",
    )
    RELOAD_FAILED = "reload_failed", "Changed, but the service reload failed"
    TIMED_OUT = "timed_out", "Stopped at the runtime limit"
    KILLED = "killed", "Terminated by a signal"
    OUTCOME_UNKNOWN = "outcome_unknown", "Outcome unknown: no native record of the run remains"

    @classmethod
    def refused_before_changes(cls) -> frozenset[Execution]:
        return frozenset(
            {
                cls.LOCK_CONFLICT,
                cls.UNSAFE_LOCK,
                cls.BOOT_CHANGED,
                cls.EXPIRED,
                cls.OTHER_RUN_ACTIVE,
                cls.DRIFT,
                cls.PACKAGE_MANAGER_BUSY,
                cls.CAPACITY,
                cls.TRANSACTION_REFUSED,
                cls.ACCOUNT_BUSY,
                cls.RENEWAL_ACTIVE,
                cls.DRIVER_UNAVAILABLE,
                cls.PRINCIPAL_CONFLICT,
                cls.STATEMENT_REFUSED,
            }
        )


class Verification(models.TextChoices):
    PENDING = "pending", "Not checked yet"
    PASSED = "passed", "Postconditions hold"
    FAILED = "failed", "Postconditions do not hold"
    UNAVAILABLE = "unavailable", "Could not be checked"
    NOT_APPLICABLE = "not_applicable", "Not applicable: the execution did not succeed"


class PlanNativeUnit(ImmutableRecord):
    """A finished bootstrap unit a cleanup plan clears, as preparation observed it."""

    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="native_units"
    )
    position = models.PositiveSmallIntegerField()
    unit_name = models.CharField(max_length=80)
    invocation_id = models.CharField(max_length=32)
    active_state = models.CharField(max_length=30)
    sub_state = models.CharField(max_length=30)
    result = models.CharField(max_length=30)
    exec_main_status = models.PositiveSmallIntegerField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.unit_name


class ApplyRun(RemoteOperation):
    """docs/adr/0004-serialize-remote-operations-in-one-table.md#consequences"""

    KIND: ClassVar[str] = RemoteOperation.Kind.APPLY

    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.SET_NULL, null=True, related_name="apply_run"
    )
    # A revision is applied at most once, so duplicate requests converge on one run.
    plan_number = models.PositiveBigIntegerField(unique=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    requested_by_name = models.CharField(max_length=150)
    server_name = models.CharField(max_length=100)
    action = models.CharField(max_length=20, choices=Action)
    intent = models.CharField(max_length=200)
    profile_revision = models.PositiveSmallIntegerField()
    # docs/adr/0008-review-each-ubuntu-release-by-its-own-policy.md#the-release-decides-every-rule
    release = models.CharField(max_length=5)
    # The host key, boot and deadline the plan was reviewed with.
    reviewed_host_key = models.CharField(max_length=200)
    boot_id = models.CharField(max_length=36)
    admission_deadline_centiseconds = models.BigIntegerField()
    admission_expires_at = models.DateTimeField()
    # The reviewed effects, one "Kind. Text" per line.
    effects = models.TextField()
    # The reviewed changes, one per line: each package transition with its version,
    # architecture and archives, or each finished unit a cleanup clears with its invocation.
    reviewed_changes = models.TextField(blank=True)
    # The transient systemd unit, such as "barectl-apply-<32 hex digits>.service".
    unit_name = models.CharField(max_length=80, unique=True)
    # systemd's identifier of the unit's invocation, once native evidence showed it.
    invocation_id = models.CharField(max_length=32, blank=True)
    # When the server acknowledged the submission.
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    # SHA-256 of /var/lib/dpkg/status before submission, to verify no package changed.
    dpkg_status_before = models.CharField(max_length=64, blank=True)
    # SHA-256 of the sorted automatic installation marks before submission, to verify a
    # package change kept every earlier package's mark.
    auto_marks_before = models.CharField(max_length=64, blank=True)
    execution = models.CharField(max_length=30, choices=Execution, default=Execution.NOT_SUBMITTED)
    # The payload's exit status, once native evidence showed it exited.
    exit_status = models.PositiveSmallIntegerField(null=True, blank=True)
    verification = models.CharField(
        max_length=20, choices=Verification, default=Verification.PENDING
    )
    # docs/adr/0006-use-native-bootstrap-execution.md#unknown-outcomes
    unknown_acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    unknown_acknowledged_by_name = models.CharField(max_length=150, blank=True)
    unknown_acknowledged_at = models.DateTimeField(null=True, blank=True)
    # Set with an acknowledgement until a check has tried to close the run with it.
    closure_requested_at = models.DateTimeField(null=True, blank=True)
    # Why the latest closure attempt could not close the run, in the pages' wording.
    closure_blocked = models.TextField(blank=True)

    class Meta:
        # Access to apply runs is granted on ConfigurationPlan.
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} apply of plan {self.plan_number}"
