from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models
from django.db.models import Q
from django.db.models.base import ModelBase
from django.db.models.expressions import Combinable

from servers.aliases import ALIAS_MAX_LENGTH
from servers.models import Server

if TYPE_CHECKING:
    from django.utils.functional import _StrPromise

    # Django's type for Meta.permissions, declared exactly so the override is not narrower.
    type _Permissions = (
        list[tuple[str, str | _StrPromise]] | tuple[tuple[str, str | _StrPromise], ...]
    )


class RemoteOperation(models.Model):
    """docs/adr/0004-serialize-remote-operations-in-one-table.md"""

    class Kind(models.TextChoices):
        DISCOVERY = "discovery", "Discovery"
        PLAN_PREPARATION = "plan_preparation", "Plan preparation"
        APPLY = "apply", "Apply"

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        RECONCILING = "reconciling", "Reconciling"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    ACTIVE: ClassVar[tuple[Status, ...]] = (Status.QUEUED, Status.RUNNING, Status.RECONCILING)
    # The kind a new row of this model records. Each kind's details model sets its own.
    KIND: ClassVar[str] = ""

    # PROTECT refuses deleting the server while any operation is attached, including one
    # queued by a concurrent request after removal checked for active ones.
    server = models.ForeignKey(
        Server, on_delete=models.PROTECT, null=True, related_name="remote_operations"
    )
    kind = models.CharField(max_length=20, choices=Kind)
    # The alias the operation connects with, recorded when it was queued.
    ssh_alias = models.CharField("SSH alias", max_length=ALIAS_MAX_LENGTH)
    status = models.CharField(max_length=12, choices=Status, default=Status.QUEUED)
    queued_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    dispatched_at = models.DateTimeField(null=True, blank=True)
    # Operator-facing; never raw exception or remote output.
    failure = models.TextField(blank=True)
    # The verified host key, such as "ssh-ed25519 SHA256:…". Public information.
    host_key = models.CharField(max_length=200, blank=True)
    revision = models.PositiveIntegerField(default=0)
    check_requested_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["-queued_at", "-pk"]
        # The released stack grants access per kind, on each kind's own models. Changes on
        # the change engine are granted per scope: the review's consent level decides which
        # apply permission they need (operations.consent).
        default_permissions: ClassVar[Sequence[str]] = ()
        permissions: ClassVar[_Permissions] = [
            ("view_site", "Can view sites"),
            ("view_evidence", "Can view native evidence"),
            ("prepare_change", "Can prepare changes"),
            ("apply_site_change", "Can apply changes confined to one site"),
            ("apply_shared_change", "Can apply changes that affect shared services"),
            ("apply_destructive_change", "Can apply changes that lose data"),
        ]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["server"],
                # ACTIVE, spelled out because Meta cannot read the class's names; a test
                # keeps the two equal.
                condition=Q(status__in=["queued", "running", "reconciling"]),
                name="one_active_remote_operation_per_server",
            ),
            models.CheckConstraint(
                condition=Q(kind__in=["discovery", "plan_preparation", "apply"]),
                name="remote_operation_kind_known",
            ),
            models.CheckConstraint(
                condition=Q(server__isnull=False)
                | Q(kind="apply", status__in=["succeeded", "failed"]),
                name="only_finished_apply_runs_outlive_their_server",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} {self.get_kind_display().lower()} of {self.ssh_alias}"

    @override
    def save(
        self,
        *,
        force_insert: bool | tuple[ModelBase, ...] = False,
        force_update: bool = False,
        using: str | None = None,
        update_fields: Iterable[str] | None = None,
    ) -> None:
        if self._state.adding and not self.kind:
            self.kind = self.KIND
        super().save(
            force_insert=force_insert,
            force_update=force_update,
            using=using,
            update_fields=update_fields,
        )


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
    INHIBITION_FAILED = (
        "inhibition_failed",
        "Refused: Certbot's packaged renewal could not be inhibited",
    )
    PACKAGE_MANAGER_BUSY = "package_manager_busy", "Refused: the package manager is busy"
    CAPACITY = "capacity", "Refused: too many finished runs are retained"
    TRANSACTION_REFUSED = (
        "transaction_refused",
        "Refused: APT's actual transaction differed from the reviewed one",
    )
    # docs/adr/0012-publish-site-files-without-replacing-them.md
    ACCOUNT_BUSY = "account_busy", "Refused: the account tool could not change the accounts"
    # docs/wordpress.md
    TOOL_REFUSED = (
        "tool_refused",
        "Refused: the authenticated tool could not be established",
    )
    # docs/wordpress.md#applying-an-installation
    ARTIFACT_REFUSED = (
        "artifact_refused",
        "Refused: the application's artifact or toolchain was not admitted",
    )
    GATE_REFUSED = (
        "gate_refused",
        "Refused: the gate was not verified; the site file was restored",
    )
    # docs/wordpress.md#finishing-a-partial-installation
    NOT_GATED = (
        "not_gated",
        "Refused: the site is not behind a verified provisioning gate",
    )
    EDITED_FILES = (
        "edited_files",
        "Refused: existing release files differ from the pinned archive",
    )
    NOT_SERVING = (
        "not_serving",
        "Installed, but HTTPS did not verify; the gate was restored",
    )
    EXPOSURE_UNCERTAIN = (
        "exposure_uncertain",
        "Installed, but HTTPS did not verify; the gate is not proven back",
    )
    # docs/wordpress.md#inspecting-wordpress
    INSPECTION_REFUSED = (
        "inspection_refused",
        "Refused: the application could not be inspected as reviewed",
    )
    # docs/wordpress.md#maintaining-wordpress
    MAINTENANCE_REFUSED = (
        "maintenance_refused",
        "Refused: the application could not be maintained as reviewed",
    )
    # docs/wordpress.md#php-runtime
    CAPABILITY_FAILED = (
        "capability_failed",
        "Changed, but the CLI and the site pool do not agree on the capabilities",
    )
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
                cls.INHIBITION_FAILED,
                cls.TOOL_REFUSED,
                cls.ARTIFACT_REFUSED,
                cls.GATE_REFUSED,
                cls.NOT_GATED,
                cls.EDITED_FILES,
                cls.INSPECTION_REFUSED,
                cls.MAINTENANCE_REFUSED,
            }
        )


class Verification(models.TextChoices):
    PENDING = "pending", "Not checked yet"
    PASSED = "passed", "Postconditions hold"
    FAILED = "failed", "Postconditions do not hold"
    UNAVAILABLE = "unavailable", "Could not be checked"
    NOT_APPLICABLE = "not_applicable", "Not applicable: the execution did not succeed"
