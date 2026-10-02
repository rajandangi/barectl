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


class StagingRequest(ImmutableRecord):
    """What the operator asked to order against the staging authority."""

    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.CASCADE, primary_key=True, related_name="staging_request"
    )
    identifier = models.CharField(max_length=24)
    # The ACME contact address for the isolated staging account, and the directory URL of
    # the authority the request chose from the allowlist.
    email = models.EmailField(max_length=254)
    authority = models.CharField(max_length=200)
    terms_accepted = models.BooleanField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Staging order of {self.identifier}"


class ReadinessName(ImmutableRecord):
    """One site name's fresh DNS answers in a readiness or staging review."""

    plan = models.ForeignKey(
        ConfigurationPlan, on_delete=models.CASCADE, related_name="readiness_names"
    )
    position = models.PositiveSmallIntegerField()
    name = models.CharField(max_length=255)
    a = models.TextField(blank=True)
    aaaa = models.TextField(blank=True)
    cname = models.CharField(max_length=255, blank=True)
    caa = models.TextField(blank=True)
    problem = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]

    @override
    def __str__(self) -> str:
        return self.name

    @property
    def a_list(self) -> tuple[str, ...]:
        return tuple(self.a.splitlines())

    @property
    def aaaa_list(self) -> tuple[str, ...]:
        return tuple(self.aaaa.splitlines())

    @property
    def caa_list(self) -> tuple[str, ...]:
        return tuple(self.caa.splitlines())


class PlanTlsReadiness(ImmutableRecord):
    """A readiness review's own facts: the site, the names and the authority."""

    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="readiness"
    )
    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=10)
    authority = models.CharField(max_length=200)
    authority_name = models.CharField(max_length=100)
    webroot = models.CharField(max_length=200)
    # Whether the site's file publishes IPv6 listeners, so AAAA records are expected.
    ipv6 = models.BooleanField()

    @property
    def name_list(self) -> tuple[str, ...]:
        return tuple(name.name for name in self.plan.readiness_names.all())

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"TLS readiness of {self.identifier}"


class Staging(ImmutableRecord):
    """A staging order's reviewed facts: what the run sends and where its artifacts go."""

    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=10)
    # The site's canonical names, one per line.
    names = models.TextField()
    webroot = models.CharField(max_length=200)
    authority = models.CharField(max_length=200)
    authority_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=254)
    # The reviewed staging lineage's name inside the isolated configuration.
    cert_name = models.CharField(max_length=32)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Staging order of {self.identifier}"

    @property
    def name_list(self) -> tuple[str, ...]:
        return tuple(self.names.splitlines())


class PlanTlsStaging(Staging):
    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="staging"
    )
    payload_bytes = models.PositiveIntegerField(null=True)


class RunStaging(Staging):
    """An apply run's copy of its plan's order, kept with the run's audit."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="staging"
    )


class StagingRunResult(ImmutableRecord):
    """What verification read after a staging order: the staged certificate's evidence."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="staging_result"
    )
    # openssl x509's subject, dates and names of the staged certificate; empty when the
    # run failed before one existed.
    subject = models.CharField(max_length=200, blank=True)
    not_before = models.CharField(max_length=60, blank=True)
    not_after = models.CharField(max_length=60, blank=True)
    names = models.TextField(blank=True)
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Verification of run {self.run_id}"
