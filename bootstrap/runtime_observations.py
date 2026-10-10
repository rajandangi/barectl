"""Typed runtime evidence retained with a connection snapshot."""

from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models

from .runtime_services import PhpRuntimeObservation


class PhpRuntimeSnapshot(models.Model):
    snapshot = models.OneToOneField("discovery.DiscoverySnapshot", on_delete=models.CASCADE)
    default_branch = models.CharField(max_length=3, blank=True)
    default_path = models.CharField(max_length=100, blank=True)
    default_mode = models.CharField(max_length=6, blank=True)
    default_package = models.CharField(max_length=30, blank=True)
    default_version = models.CharField(max_length=100, blank=True)
    architecture = models.CharField(max_length=6, blank=True)
    installed = models.CharField(max_length=20, blank=True)
    supply = models.CharField(max_length=6, blank=True)
    failure = models.TextField(blank=True)
    fingerprint = models.CharField(max_length=64, blank=True)
    fresh = models.BooleanField(default=False)

    class Meta:
        app_label = "bootstrap"
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"PHP runtime evidence for snapshot {self.snapshot_id}"


def save(snapshot_id: int, observed: PhpRuntimeObservation) -> None:
    default = observed.default
    PhpRuntimeSnapshot.objects.create(
        snapshot_id=snapshot_id,
        default_branch=default.branch if default else "",
        default_path=default.path if default else "",
        default_mode=default.mode if default else "",
        default_package=default.package if default else "",
        default_version=default.version if default else "",
        architecture=default.architecture if default else "",
        installed="\n".join(observed.installed),
        supply=observed.supply or "",
        failure=observed.failure,
        fingerprint=observed.fingerprint,
        fresh=observed.fresh,
    )
