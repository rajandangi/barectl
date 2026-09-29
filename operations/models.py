from collections.abc import Iterable, Sequence
from typing import ClassVar, override

from django.db import models
from django.db.models import Q
from django.db.models.base import ModelBase
from django.db.models.expressions import Combinable

from servers.aliases import ALIAS_MAX_LENGTH
from servers.models import Server


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
        # Access is granted per kind, on each kind's own models.
        default_permissions: ClassVar[Sequence[str]] = ()
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
