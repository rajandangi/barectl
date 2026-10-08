"""A WP-CLI setup plan's typed review records (docs/wordpress.md).

Each is immutable and deleted with its plan or run; nothing here is written to the
server. The controller never records key material: the pins are the public review's own
facts, and the payload rechecks them on the server.
"""

from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models

from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord


class WpcliTool(ImmutableRecord):
    """The reviewed authenticated artifact and where the run installs it."""

    version = models.CharField(max_length=20)
    # The pinned official artifacts and the signing identity the run authenticates with.
    phar_url = models.URLField(max_length=300)
    signature_url = models.URLField(max_length=300)
    key_url = models.URLField(max_length=300)
    fingerprint = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64)
    path = models.CharField(max_length=200)
    # Whether the installation directory exists as reviewed; a run creates it otherwise.
    creates_directory = models.BooleanField()
    # Whether the artifact existed with its reviewed bytes when the plan was prepared.
    exists = models.BooleanField()
    payload_bytes = models.PositiveIntegerField(null=True)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"WP-CLI {self.version} at {self.path}"


class PlanWpcliTool(WpcliTool):
    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="wpcli_tool"
    )


class RunWpcliTool(WpcliTool):
    """An apply run's copy of its plan's tool review, kept with the run's audit."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="wpcli_tool"
    )


class WpcliRunResult(ImmutableRecord):
    """What verification read after a successful setup run."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="wpcli_result"
    )
    # Each difference from the reviewed setup, one per line; empty when none.
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Verification of run {self.run_id}"
