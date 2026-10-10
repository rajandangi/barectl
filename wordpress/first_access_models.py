"""Encrypted browser first access.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models


class FirstAccessDelivery(models.Model):
    run = models.OneToOneField("bootstrap.ApplyRun", on_delete=models.CASCADE, primary_key=True)
    requested_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True)
    key_sha256 = models.CharField(max_length=64)
    ciphertext = models.CharField(max_length=684, blank=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)
    retrieved_at = models.DateTimeField(null=True)
    unavailable = models.BooleanField(default=False)

    class Meta:
        app_label = "wordpress"
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Encrypted first access for run {self.run_id}"
