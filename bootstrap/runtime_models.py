"""Local PHP runtime requests and immutable native reviews (docs/site-creation.md)."""

from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models
from django.db.models import Q

from .models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation


class RuntimeChange(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Changing runtime"
        SUCCEEDED = "succeeded", "Runtime verified"
        FAILED = "failed", "Runtime change stopped"

    server = models.ForeignKey("servers.Server", on_delete=models.SET_NULL, null=True)
    requested_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=30)
    branch = models.CharField(max_length=3)
    identifier = models.CharField(max_length=24, blank=True)
    ssh_alias = models.CharField(max_length=253)
    host_key = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=12, choices=Status, default=Status.ACTIVE)
    failure = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["server"],
                condition=Q(status="active"),
                name="one_active_php_runtime_change",
            )
        ]

    @override
    def __str__(self) -> str:
        return f"PHP {self.branch} runtime change {self.pk}"


class RuntimeChangeStep(models.Model):
    change = models.ForeignKey(RuntimeChange, on_delete=models.CASCADE, related_name="steps")
    position = models.PositiveSmallIntegerField()
    preparation = models.OneToOneField(PlanPreparation, on_delete=models.SET_NULL, null=True)
    run = models.OneToOneField(ApplyRun, on_delete=models.SET_NULL, null=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["change", "position"], name="one_step_per_runtime_change"
            )
        ]

    @override
    def __str__(self) -> str:
        return f"Runtime change {self.change_id} step {self.position}"


class RuntimeRequest(ImmutableRecord):
    preparation = models.OneToOneField(PlanPreparation, on_delete=models.CASCADE)
    branch = models.CharField(max_length=3)
    identifier = models.CharField(max_length=24, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"PHP {self.branch} for {self.identifier or 'the server default'}"


class RuntimeSelection(ImmutableRecord):
    branch = models.CharField(max_length=3)
    before_branch = models.CharField(max_length=3, blank=True)
    before_mode = models.CharField(max_length=6, blank=True)
    default_digest = models.CharField(max_length=64)
    source_digest = models.CharField(max_length=64, blank=True)
    # An installation phase uses the existing exact package profile and its verification.
    package_action = models.CharField(max_length=30, blank=True)
    identifier = models.CharField(max_length=24, blank=True)
    old_branch = models.CharField(max_length=3, blank=True)
    old_revision = models.PositiveSmallIntegerField(default=4)
    site_digest = models.CharField(max_length=64, blank=True)
    old_site = models.TextField(blank=True)
    new_site = models.TextField(blank=True)
    old_pool = models.TextField(blank=True)
    new_pool = models.TextField(blank=True)
    names = models.TextField(blank=True)
    token = models.CharField(max_length=32, blank=True)
    body_sha256 = models.CharField(max_length=64, blank=True)
    database_engine = models.CharField(max_length=12, blank=True)
    database_digest = models.CharField(max_length=64, blank=True)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"PHP {self.branch} runtime selection"


class RuntimePlan(RuntimeSelection):
    plan = models.OneToOneField(ConfigurationPlan, on_delete=models.CASCADE, related_name="runtime")


class RuntimeRun(RuntimeSelection):
    run = models.OneToOneField(ApplyRun, on_delete=models.CASCADE, related_name="runtime")


class PackagePhpDefault(ImmutableRecord):
    plan = models.OneToOneField(ConfigurationPlan, on_delete=models.CASCADE)
    branch = models.CharField(max_length=3)
    fingerprint = models.CharField(max_length=64)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Retain the server PHP {self.branch} default"


class PackagePhpDefaultRequest(ImmutableRecord):
    preparation = models.OneToOneField(PlanPreparation, on_delete=models.CASCADE)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Preserve PHP default for preparation {self.preparation_id}"
