from collections.abc import Iterable, Sequence
from datetime import timedelta
from typing import TYPE_CHECKING, ClassVar, NoReturn, override

from django.conf import settings
from django.db import models
from django.db.models import F, Q
from django.db.models.base import ModelBase
from django.db.models.expressions import Combinable

from operations.inputs import empty_inputs
from servers.aliases import ALIAS_MAX_LENGTH
from servers.models import Server

if TYPE_CHECKING:
    from django.utils.functional import _StrPromise

    # Django's type for Meta.permissions, declared exactly so the override is not narrower.
    type _Permissions = (
        list[tuple[str, str | _StrPromise]] | tuple[tuple[str, str | _StrPromise], ...]
    )

# docs/adr/0035-one-change-engine-with-effect-derived-consent.md: the scope permissions of
# the whole change engine. Kinds never carry permissions of their own.
VIEW_CHANGES: str = "operations.view_changes"
CHANGE_SITE: str = "operations.change_site"
CHANGE_SHARED: str = "operations.change_shared"
CHANGE_DESTRUCTIVE: str = "operations.change_destructive"
MANAGE_SECRETS: str = "operations.manage_secrets"

ADMISSION_CENTISECONDS = 15 * 60 * 100
# docs/adr/0032-keep-secrets-in-private-native-files.md#the-confidential-input-channel: a
# sealed value a worker has not sent within this long is treated as expired.
CONFIDENTIAL_LIFETIME = timedelta(minutes=10)


class RemoteOperation(models.Model):
    """docs/adr/0004-serialize-remote-operations-in-one-table.md"""

    class Kind(models.TextChoices):
        DISCOVERY = "discovery", "Discovery"
        CHANGE_PREPARATION = "change_preparation", "Change preparation"
        CHANGE_APPLY = "change_apply", "Change apply"

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
    connection = models.ForeignKey(
        "servers.ConnectionDefinition", on_delete=models.PROTECT, null=True, related_name="+"
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
                condition=Q(
                    kind__in=[
                        "discovery",
                        "change_preparation",
                        "change_apply",
                    ]
                ),
                name="remote_operation_kind_known",
            ),
            models.CheckConstraint(
                condition=Q(server__isnull=False)
                | Q(kind="change_apply", status__in=["succeeded", "failed"]),
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


class Consent(models.TextChoices):
    """docs/adr/0035-one-change-engine-with-effect-derived-consent.md: what applying a
    review needs. Derived from the declared effects, never chosen by a kind."""

    READ = "read", "Read"
    SITE = "site", "Site"
    SHARED = "shared", "Shared"
    DESTRUCTIVE = "destructive", "Destructive"


class Result(models.TextChoices):
    """The change engine's one small outcome contract: a payload reports one structured
    result line in the journal and exits in one of these classes
    (docs/adr/0035-one-change-engine-with-effect-derived-consent.md)."""

    NOT_SUBMITTED = "not_submitted", "Not submitted"
    SUBMITTED = "submitted", "Submitted; not yet confirmed on the server"
    NOT_FOUND = "not_found", "No native record found"
    RUNNING = "running", "Running on the server"
    SUCCEEDED = "succeeded", "Completed successfully"
    REFUSED = "refused", "Refused before any change"
    PARTIAL = "partial", "Stopped after changing: partly applied"
    FAILED = "failed", "Failed; what changed is unknown"
    LOCK_BUSY = "lock_busy", "Refused: another change holds the mutation lock"
    TIMED_OUT = "timed_out", "Stopped at the runtime limit"
    OUTCOME_UNKNOWN = "outcome_unknown", "Outcome unknown: no native record of the run remains"

    @classmethod
    def refused_before_changes(cls) -> frozenset[Result]:
        return frozenset({cls.REFUSED, cls.LOCK_BUSY})


class Verification(models.TextChoices):
    PENDING = "pending", "Not checked yet"
    PASSED = "passed", "Postconditions hold"
    FAILED = "failed", "Postconditions do not hold"
    UNAVAILABLE = "unavailable", "Could not be checked"
    NOT_APPLICABLE = "not_applicable", "Not applicable: the change did not succeed"


class ChangeRecord(models.Model):
    """A record the engine stores once and never edits."""

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
    raise ValueError("Change records are immutable; prepare a new review instead.")


class PreparationQuerySet(models.QuerySet["ChangePreparation"]):
    @override
    def update(self, **kwargs: object) -> int:
        if {"kind_slug", "inputs"} & kwargs.keys():
            raise ValueError("Preparation inputs are immutable; prepare a new review.")
        return super().update(**kwargs)


class ChangePreparation(RemoteOperation):
    """docs/adr/0035-one-change-engine-with-effect-derived-consent.md"""

    KIND: ClassVar[str] = RemoteOperation.Kind.CHANGE_PREPARATION

    kind_slug = models.CharField(max_length=40)
    inputs = models.JSONField(default=empty_inputs)
    # The Django plugin narrows this generated manager beyond the inherited manager.
    objects: ClassVar[models.Manager[ChangePreparation]] = PreparationQuerySet.as_manager()  # type: ignore[mutable-override]

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        base_manager_name = "objects"

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} change preparation of {self.kind_slug}"

    @override
    def save(
        self,
        *,
        force_insert: bool | tuple[ModelBase, ...] = False,
        force_update: bool = False,
        using: str | None = None,
        update_fields: Iterable[str] | None = None,
    ) -> None:
        if not self._state.adding:
            original = type(self).objects.using(using).get(pk=self.pk)
            if original.kind_slug != self.kind_slug or original.inputs != self.inputs:
                raise ValueError("Preparation inputs are immutable; prepare a new review.")
        super().save(
            force_insert=True if self._state.adding else force_insert,
            force_update=force_update,
            using=using,
            update_fields=update_fields,
        )


class ChangeReview(ChangeRecord):
    """One stored review: a typed core every change shares, plus the kind's versioned
    document. A run references it; nothing copies it."""

    preparation = models.OneToOneField(
        ChangePreparation,
        on_delete=models.SET_NULL,
        null=True,
        related_name="review",
    )
    kind_slug = models.CharField(max_length=40)
    intent = models.CharField(max_length=200)
    eligible = models.BooleanField()
    no_changes = models.BooleanField(default=False)
    # Derived from the declared effects by the engine; a kind never states it.
    consent = models.CharField(max_length=12, choices=Consent)
    # The kind writes a secret through the confidential input channel, so applying also
    # needs the manage-secrets permission (docs/adr/0032-keep-secrets-in-private-native-files.md).
    writes_secrets = models.BooleanField(default=False)
    affected_sites = models.JSONField(default=list)
    # The declared effects: [{"scope": "site", "text": …, "sites": […]}]
    effects = models.JSONField(default=list)
    ssh_alias = models.CharField("SSH alias", max_length=ALIAS_MAX_LENGTH)
    # The verified host key, such as "ssh-ed25519 SHA256:…". Public information.
    host_key = models.CharField(max_length=200, blank=True)
    boot_id = models.CharField(max_length=36, blank=True)
    # /proc/uptime at the start of collection, in hundredths of a second, and the deadline
    # on the same clock after which the review can no longer be admitted.
    uptime_centiseconds = models.BigIntegerField(null=True)
    admission_deadline_centiseconds = models.BigIntegerField(null=True)
    # The controller's clock when collection started, and its estimate of the deadline.
    collected_at = models.DateTimeField()
    admission_expires_at = models.DateTimeField()
    # The fixed command listing the affected sites, empty when the change names none; the
    # payload re-runs it under the mutation lock and compares the digest.
    sites_read = models.TextField(blank=True)
    sites_digest = models.CharField(max_length=64, blank=True)
    # The kind's own review document, versioned by the kind: {"version": 1, …}.
    document = models.JSONField(default=dict)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        permissions: ClassVar[_Permissions] = [
            ("view_changes", "Can view changes"),
            ("change_site", "Can change a site"),
            ("change_shared", "Can change shared resources"),
            ("change_destructive", "Can make destructive changes"),
            ("manage_secrets", "Can manage secrets"),
        ]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.CheckConstraint(
                condition=Q(uptime_centiseconds__isnull=True, admission_deadline_centiseconds=None)
                | Q(
                    admission_deadline_centiseconds=F("uptime_centiseconds")
                    + ADMISSION_CENTISECONDS
                ),
                name="review_admission_deadline_fifteen_minutes",
            ),
            models.CheckConstraint(
                condition=Q(eligible=False)
                | (~Q(boot_id="") & Q(uptime_centiseconds__isnull=False)),
                name="eligible_review_has_boot_and_deadline",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Review {self.pk}: {self.kind_slug}"

    @property
    def acknowledgement(self) -> str:
        """The acknowledgement a kind's review requires before apply, or an empty string.

        The kind states it in its document; the engine and the views refuse an apply that
        does not carry the confirmation, so a forged POST without it changes nothing.
        """
        value = self.document.get("acknowledgement", "")
        return value if isinstance(value, str) else ""


class ChangeRun(RemoteOperation):
    """docs/adr/0035-one-change-engine-with-effect-derived-consent.md: a run refers to the
    one stored review it applies, and its protected reference keeps that review for the
    run's audit."""

    KIND: ClassVar[str] = RemoteOperation.Kind.CHANGE_APPLY

    review = models.OneToOneField(ChangeReview, on_delete=models.PROTECT, related_name="run")
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    requested_by_name = models.CharField(max_length=150)
    server_name = models.CharField(max_length=100)
    # The transient systemd unit, such as "barectl-apply-<32 hex digits>.service"; it
    # collects itself, so its evidence lives in the journal.
    unit_name = models.CharField(max_length=80, unique=True)
    # systemd's identifier of the unit's invocation, once native evidence showed it.
    invocation_id = models.CharField(max_length=32, blank=True)
    # When the server acknowledged the submission.
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    execution = models.CharField(max_length=20, choices=Result, default=Result.NOT_SUBMITTED)
    # The payload's exit status, once native evidence showed it exited.
    exit_status = models.PositiveSmallIntegerField(null=True, blank=True)
    # The structured result line's reason, such as "affected_sites"; the class itself is
    # the execution.
    result_reason = models.CharField(max_length=30, blank=True)
    progress_stage = models.CharField(max_length=160, blank=True)
    # docs/adr/0032-keep-secrets-in-private-native-files.md#the-confidential-input-channel:
    # one sealed value the run carries, readable only while this worker's key is current,
    # and cleared the moment it is staged on the server.
    secret_sealed = models.TextField(blank=True)
    secret_expires_at = models.DateTimeField(null=True, blank=True)
    verification = models.CharField(
        max_length=20, choices=Verification, default=Verification.PENDING
    )
    # A Shared change's operator acknowledged the listed affected sites when requesting it.
    sites_acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    sites_acknowledged_at = models.DateTimeField(null=True, blank=True)
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
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.CheckConstraint(
                condition=Q(secret_sealed="") | Q(secret_expires_at__isnull=False),
                name="run_sealed_secret_has_expiry",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} change run of review {self.review_id}"
