"""A TLS plan's typed review records (docs/tls.md).

Each is immutable and deleted with its plan or run; nothing here is written to the server.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models
from django.db.models.expressions import Combinable

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


class RenewalFile(ImmutableRecord):
    """One file of the guarded renewal, with its complete bytes (docs/tls.md)."""

    class Role(models.TextChoices):
        DEPLOY_HOOK = "deploy_hook", "Deploy hook"
        RENEW_WRAPPER = "renew_wrapper", "Renewal wrapper"
        DROP_IN = "dropin", "certbot.service drop-in"

    position = models.PositiveSmallIntegerField()
    role = models.CharField(max_length=20, choices=Role)
    path = models.CharField(max_length=200)
    mode = models.CharField(max_length=4)
    content = models.TextField()
    content_sha256 = models.CharField(max_length=64)
    # Whether it existed with these bytes when the plan was prepared; a run publishes only
    # the others.
    exists = models.BooleanField()

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.path


class PlanRenewalFile(RenewalFile):
    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="renewal_files"
    )


class RunRenewalFile(RenewalFile):
    run = models.ForeignKey(ApplyRun, on_delete=models.CASCADE, related_name="renewal_files")


class PlanRenewalObservation(ImmutableRecord):
    """Renewal's native state when a setup plan was prepared: a read-only inspection."""

    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="renewal"
    )
    # systemd's own words, such as "enabled", "active" or "exit-code"; empty when absent.
    timer_enablement = models.CharField(max_length=30, blank=True)
    timer_state = models.CharField(max_length=30, blank=True)
    last_trigger = models.CharField(max_length=60, blank=True)
    next_elapse = models.CharField(max_length=60, blank=True)
    last_result = models.CharField(max_length=30, blank=True)
    last_status = models.CharField(max_length=10, blank=True)
    last_exit = models.CharField(max_length=60, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Renewal state of plan {self.plan_id}"


class SetupRunResult(ImmutableRecord):
    """What verification read after a successful setup run."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="setup_result"
    )
    # Each difference from the reviewed setup, one per line; empty when none.
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Verification of run {self.run_id}"


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
