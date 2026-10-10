"""Explicit browser recovery.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models

from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation

from .inspection_models import InspectionReview

if TYPE_CHECKING:
    from bootstrap.models import _Permissions


class AccessResetRequest(ImmutableRecord):
    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.CASCADE, primary_key=True, related_name="access_request"
    )
    identifier = models.CharField(max_length=24)
    admin_login = models.CharField(max_length=60)
    first_access_spki = models.CharField(max_length=1024)
    first_access_expires_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        permissions: ClassVar[_Permissions] = [
            ("manage_wordpress_credentials", "Can explicitly reset WordPress administrator access")
        ]


class AccessReview(InspectionReview):
    account_id = models.PositiveBigIntegerField()
    admin_login = models.CharField(max_length=60)
    admin_email = models.CharField(max_length=100)
    first_name = models.CharField(max_length=100, blank=True)
    site_digest = models.CharField(max_length=64)
    wpcli_digest = models.CharField(max_length=64)
    state_digest = models.CharField(max_length=64)
    account_digest = models.CharField(max_length=64)
    password_digest = models.CharField(max_length=64)
    first_access_spki = models.CharField(max_length=1024)
    first_access_expires_at = models.DateTimeField()

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()


class PlanWordpressAccess(AccessReview):
    plan = models.OneToOneField(
        ConfigurationPlan,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="wordpress_access",
    )


class RunWordpressAccess(AccessReview):
    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="wordpress_access"
    )


class AccessResetIntent(models.Model):
    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.CASCADE, primary_key=True, related_name="access_intent"
    )
    run = models.OneToOneField(ApplyRun, on_delete=models.SET_NULL, null=True, related_name="+")
    status = models.CharField(max_length=12, default="active")
    failure = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"WordPress recovery intent {self.preparation_id}"
