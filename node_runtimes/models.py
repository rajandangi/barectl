"""Controller-only Node requests and reviewed changes (docs/node-runtimes-native-design.md)."""

from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models

from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation


class RuntimeRequest(ImmutableRecord):
    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.CASCADE, primary_key=True, related_name="node_request"
    )
    version = models.CharField(max_length=20)
    identifier = models.CharField(max_length=24, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()


class RuntimeReview(ImmutableRecord):
    version = models.CharField(max_length=20)
    identifier = models.CharField(max_length=24, blank=True)
    architecture = models.CharField(max_length=10)
    digest = models.CharField(max_length=64)
    default_before = models.CharField(max_length=20, blank=True)
    pin_before = models.CharField(max_length=20, blank=True)
    executable = models.CharField(max_length=200)
    installs_runtime = models.BooleanField()

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()


class PlanNodeRuntime(RuntimeReview):
    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="node_runtime"
    )


class RunNodeRuntime(RuntimeReview):
    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="node_runtime"
    )


class NodeRuntimeSnapshot(ImmutableRecord):
    snapshot = models.OneToOneField(
        "discovery.DiscoverySnapshot",
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="node_runtime",
    )
    default = models.CharField(max_length=20, blank=True)
    installed = models.TextField(blank=True)
    site_pins = models.TextField(blank=True)
    failure = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()


class RuntimeChange(models.Model):
    server = models.ForeignKey(
        "servers.Server", on_delete=models.SET_NULL, null=True, related_name="node_runtime_changes"
    )
    requested_by = models.ForeignKey(
        "auth.User", on_delete=models.SET_NULL, null=True, related_name="+"
    )
    version = models.CharField(max_length=20)
    identifier = models.CharField(max_length=24, blank=True)
    ssh_alias = models.CharField(max_length=253)
    host_key = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=12, default="active")
    failure = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["server"],
                condition=models.Q(status="active"),
                name="one_active_node_runtime_change",
            )
        ]

    @override
    def __str__(self) -> str:
        return f"Node {self.version} selection {self.pk}"


class RuntimeChangeStep(models.Model):
    change = models.ForeignKey(RuntimeChange, on_delete=models.CASCADE, related_name="steps")
    position = models.PositiveSmallIntegerField()
    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    run = models.OneToOneField(ApplyRun, on_delete=models.SET_NULL, null=True, related_name="+")

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["change", "position"], name="one_step_per_node_runtime_change"
            )
        ]

    @override
    def __str__(self) -> str:
        return f"Node selection {self.change_id} stage {self.position}"
