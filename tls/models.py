"""A TLS plan's typed review records (docs/tls.md).

Each is immutable and deleted with its plan or run; nothing here is written to the server.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models

from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation

if TYPE_CHECKING:
    from bootstrap.models import _Permissions


class TlsRequest(ImmutableRecord):
    """What the operator asked to prepare, stored with the queued preparation."""

    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.CASCADE, primary_key=True, related_name="tls_request"
    )
    identifier = models.CharField(max_length=24)

    class Meta:
        # docs/tls.md#permissions: TLS plans have their own viewers, preparers and appliers,
        # and production certificate orders a permission of their own.
        default_permissions: ClassVar[Sequence[str]] = ()
        permissions: ClassVar[_Permissions] = [
            ("view_tlsplan", "Can view TLS plans"),
            ("prepare_tlsplan", "Can prepare TLS plans"),
            ("apply_tlsplan", "Can apply TLS plans"),
            ("issue_certificate", "Can order production certificates"),
        ]

    @override
    def __str__(self) -> str:
        return f"TLS {self.identifier}"


class Challenge(ImmutableRecord):
    """One site's challenge route: the site file it replaces and what the run creates."""

    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=10)
    # The site's canonical names, one per line.
    names = models.TextField()
    ipv6 = models.BooleanField()
    # The temporary challenge probe's name part, 32 hexadecimal digits; not a secret.
    probe_token = models.CharField(max_length=32)
    # The site file's current bytes, which a backup keeps, and its replacement.
    preimage = models.TextField()
    preimage_sha256 = models.CharField(max_length=64)
    content = models.TextField()
    content_sha256 = models.CharField(max_length=64)
    # Whether the run creates /var/lib/letsencrypt and /var/backups/nginx, absent when read.
    creates_letsencrypt = models.BooleanField()
    creates_backups = models.BooleanField()

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Challenge route of {self.identifier}"

    @property
    def name_list(self) -> tuple[str, ...]:
        return tuple(self.names.splitlines())


class PlanChallenge(Challenge):
    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="challenge"
    )
    # The size of the payload built at preparation, which must fit one submission.
    payload_bytes = models.PositiveIntegerField(null=True)


class RunChallenge(Challenge):
    """An apply run's copy of its plan's challenge route, kept with the run's audit."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="challenge"
    )
    # Where the run keeps the site file's preimage, named after its unit.
    backup_path = models.CharField(max_length=200)


class ChallengeRunResult(ImmutableRecord):
    """What verification read after a successful run."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="challenge_result"
    )
    # Each difference from the reviewed changes, one per line; empty when none.
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Verification of run {self.run_id}"
