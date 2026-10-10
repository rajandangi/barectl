"""Controller-local site-creation intent and progress (docs/site-creation.md)."""

from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models
from django.db.models import Q
from django.db.models.expressions import Combinable

from bootstrap.models import ApplyRun, PlanPreparation
from discovery.models import DiscoveryAttempt


class HostingCreation(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Preparing site"
        SUCCEEDED = "succeeded", "Site prepared"
        FAILED = "failed", "Site preparation stopped"

    server = models.ForeignKey("servers.Server", on_delete=models.PROTECT, null=True)
    requested_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True)
    request_key = models.CharField(max_length=64)
    identifier = models.CharField(max_length=24)
    names = models.TextField()
    php_version = models.CharField(max_length=3)
    php_supply = models.CharField(max_length=10, blank=True)
    source_setup_needed = models.BooleanField(default=True)
    first_access_spki = models.CharField(max_length=1024, blank=True)
    node_version = models.CharField(max_length=20, blank=True)
    application = models.CharField(max_length=12, default="php")
    title = models.CharField(max_length=100, blank=True)
    admin_login = models.CharField(max_length=60, blank=True)
    admin_email = models.EmailField(max_length=100, blank=True)
    database_engine = models.CharField(max_length=12, blank=True)
    https = models.BooleanField(default=False)
    email = models.EmailField(max_length=254, blank=True)
    authority = models.URLField(max_length=500, blank=True)
    discovery_revision = models.PositiveBigIntegerField()
    ssh_alias = models.CharField(max_length=253)
    host_key = models.CharField(max_length=200)
    status = models.CharField(max_length=12, choices=Status, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True)
    failure = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["-pk"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["server"],
                condition=Q(status="active"),
                name="one_active_hosting_creation",
            ),
            models.UniqueConstraint(
                fields=["server", "request_key"], name="one_hosting_creation_intent"
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Site creation {self.pk} for {self.identifier}"


class HostingCreationStep(models.Model):
    creation = models.ForeignKey(HostingCreation, on_delete=models.CASCADE, related_name="steps")
    position = models.PositiveSmallIntegerField()
    stage = models.CharField(max_length=32)
    satisfied = models.BooleanField(default=False)
    discovery = models.OneToOneField(DiscoveryAttempt, on_delete=models.SET_NULL, null=True)
    preparation = models.OneToOneField(PlanPreparation, on_delete=models.SET_NULL, null=True)
    run = models.OneToOneField(ApplyRun, on_delete=models.SET_NULL, null=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["creation", "position"], name="one_step_per_hosting_creation"
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Site creation {self.creation_id}, {self.stage}"
