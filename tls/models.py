"""A TLS plan's typed review records (docs/tls.md).

Each is immutable and deleted with its plan or run; nothing here is written to the server.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, override

from django.db import models
from django.db.models import Q
from django.db.models.expressions import Combinable

from bootstrap.models import ApplyRun, ConfigurationPlan, ImmutableRecord, PlanPreparation

if TYPE_CHECKING:
    from bootstrap.models import _Permissions


class CertificateInstallation(models.Model):
    """The local authorization and progress of one Create and Install request."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Installing"
        SUCCEEDED = "succeeded", "HTTPS installed"
        FAILED = "failed", "Installation stopped"

    server = models.ForeignKey("servers.Server", on_delete=models.PROTECT, null=True)
    requested_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True)
    identifier = models.CharField(max_length=24)
    names = models.TextField()
    discovery_revision = models.PositiveBigIntegerField(default=0)
    email = models.EmailField(max_length=254)
    authority = models.URLField(max_length=500)
    ssh_alias = models.CharField(max_length=253)
    host_key = models.CharField(max_length=200, blank=True)
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
                name="one_active_certificate_installation",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Certificate installation {self.pk} for {self.identifier}"


class CertificateInstallationStep(models.Model):
    installation = models.ForeignKey(
        CertificateInstallation, on_delete=models.CASCADE, related_name="steps"
    )
    position = models.PositiveSmallIntegerField()
    preparation = models.OneToOneField(PlanPreparation, on_delete=models.SET_NULL, null=True)
    run = models.OneToOneField(ApplyRun, on_delete=models.SET_NULL, null=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ["position"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["installation", "position"], name="one_step_per_certificate_installation"
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Installation {self.installation_id} step {self.position}"


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
    site_revision = models.PositiveSmallIntegerField(default=3)
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


class IssuanceRequest(ImmutableRecord):
    """What the operator asked to order from the production authority."""

    preparation = models.OneToOneField(
        PlanPreparation, on_delete=models.CASCADE, primary_key=True, related_name="issuance_request"
    )
    identifier = models.CharField(max_length=24)
    # The ACME contact address for the production account.
    email = models.EmailField(max_length=254)
    terms_accepted = models.BooleanField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Production order of {self.identifier}"


class Issuance(ImmutableRecord):
    """A production order's reviewed facts: what the run sends and where its lineage goes.

    docs/tls.md#issuance. The lineage is Certbot's ordinary one, ``live/<identifier>``; no
    account credentials or key bytes are copied into Barectl.
    """

    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=10)
    site_revision = models.PositiveSmallIntegerField(default=3)
    # The site's canonical names, one per line.
    names = models.TextField()
    webroot = models.CharField(max_length=200)
    authority = models.CharField(max_length=200)
    authority_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=254)
    # The production lineage's Certbot cert-name, always the site identifier.
    cert_name = models.CharField(max_length=32)
    # The existing production account's contact, when one was present and matched the
    # reviewed address; empty when the order registers the first account.
    account = models.CharField(max_length=254, blank=True)

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Production order of {self.identifier}"

    @property
    def name_list(self) -> tuple[str, ...]:
        return tuple(self.names.splitlines())


class PlanTlsIssuance(Issuance):
    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="issuance"
    )
    payload_bytes = models.PositiveIntegerField(null=True)


class RunTlsIssuance(Issuance):
    """An apply run's copy of its plan's order, kept with the run's audit."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="issuance"
    )


class IssuanceRunResult(ImmutableRecord):
    """What verification read after a production order: the lineage's public evidence."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="issuance_result"
    )
    # openssl x509's subject, dates and names of the issued certificate; empty when the run
    # failed before one existed. Certbot 2.x issues SAN-only certificates, so the subject
    # may be empty.
    subject = models.CharField(max_length=200, blank=True)
    not_before = models.CharField(max_length=60, blank=True)
    not_after = models.CharField(max_length=60, blank=True)
    names = models.TextField(blank=True)
    # SHA-256 of the certificate's DER bytes and its serial, the public identity both the
    # activation and discovery compare against.
    fingerprint = models.CharField(max_length=64, blank=True)
    serial = models.CharField(max_length=60, blank=True)
    # The reviewed key policy, as the private key and certificate were read: for example
    # "ecdsa secp256r1"; empty when the key could not be read.
    key_curve = models.CharField(max_length=40, blank=True)
    # Whether the private key's public half matches the certificate, and whether Certbot's
    # renewal configuration exists.
    key_matches = models.BooleanField(default=False)
    renewal = models.BooleanField(default=False)
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Production certificate of run {self.run_id}"


class ActivationRequest(ImmutableRecord):
    """What the operator asked to activate."""

    preparation = models.OneToOneField(
        PlanPreparation,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="activation_request",
    )
    identifier = models.CharField(max_length=24)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"HTTPS activation of {self.identifier}"


class Activation(ImmutableRecord):
    """An HTTPS activation's reviewed facts: the two candidate Nginx states.

    docs/tls.md#activation. The site file's preimage is kept only as the run's recovery
    material; the reviewed lineage's public identity is the certificate's DER fingerprint.
    """

    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=10)
    site_revision = models.PositiveSmallIntegerField(default=3)
    # The site's canonical names, one per line.
    names = models.TextField()
    ipv6 = models.BooleanField()
    # The site file's current bytes, which the run keeps as its recovery preimage.
    preimage = models.TextField()
    preimage_sha256 = models.CharField(max_length=64)
    # The first candidate: HTTPS with HTTP unchanged (or the preimage itself when the site
    # is already HTTPS and only the redirect remains).
    https_content = models.TextField()
    https_sha256 = models.CharField(max_length=64)
    # The second candidate: the challenge location and an HTTP redirect to the canonical
    # HTTPS name.
    redirect_content = models.TextField()
    redirect_sha256 = models.CharField(max_length=64)
    # True when the site already serves HTTPS and only the redirect remains.
    redirect_only = models.BooleanField()
    # The reviewed lineage's public identity, as the activation rechecks it.
    fingerprint = models.CharField(max_length=64)
    not_after = models.CharField(max_length=60)
    # The shared default TLS rejection server: its exact bytes and whether the run creates
    # it because it was absent.
    default_content = models.TextField()
    default_sha256 = models.CharField(max_length=64)
    creates_default = models.BooleanField()

    class Meta:
        abstract = True
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"HTTPS activation of {self.identifier}"

    @property
    def name_list(self) -> tuple[str, ...]:
        return tuple(self.names.splitlines())


class PlanTlsActivation(Activation):
    plan = models.OneToOneField(
        ConfigurationPlan, on_delete=models.CASCADE, primary_key=True, related_name="activation"
    )
    payload_bytes = models.PositiveIntegerField(null=True)


class RunTlsActivation(Activation):
    """An apply run's copy of its plan's activation, kept with the run's audit."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="activation"
    )
    # Where the run keeps the site file's preimage, named after its unit.
    backup_path = models.CharField(max_length=200)


class ActivationRunResult(ImmutableRecord):
    """What verification read after a successful activation: the served certificates."""

    run = models.OneToOneField(
        ApplyRun, on_delete=models.CASCADE, primary_key=True, related_name="activation_result"
    )
    # One "name sha256" per line: the certificate the server actually served for each name.
    served = models.TextField(blank=True)
    # The HTTP redirect's status and target, as the server itself answered.
    redirect = models.CharField(max_length=300, blank=True)
    # Whether unknown/no SNI was rejected and a Host different from valid SNI did not serve
    # the site.
    rejects_unknown = models.BooleanField(default=False)
    host_checked = models.BooleanField(default=False)
    problems = models.TextField(blank=True)
    verified_at = models.DateTimeField()

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"HTTPS activation of run {self.run_id}"


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
    site_revision = models.PositiveSmallIntegerField(default=3)
    authority = models.CharField(max_length=200)
    authority_name = models.CharField(max_length=100)
    webroot = models.CharField(max_length=200)
    # Whether the site's file publishes IPv6 listeners, so AAAA records are expected.
    ipv6 = models.BooleanField()
    # The server's own global addresses read during preparation, one per line. Empty when
    # the review was refused before the addresses were read; ``addresses_collected`` keeps
    # that distinct from a server that simply has no global address of that family.
    server_ipv4 = models.TextField(blank=True)
    server_ipv6 = models.TextField(blank=True)
    addresses_collected = models.BooleanField(default=False)

    @property
    def name_list(self) -> tuple[str, ...]:
        return tuple(name.name for name in self.plan.readiness_names.all())

    @property
    def ipv4_list(self) -> tuple[str, ...]:
        return tuple(self.server_ipv4.splitlines())

    @property
    def ipv6_list(self) -> tuple[str, ...]:
        return tuple(self.server_ipv6.splitlines())

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"TLS readiness of {self.identifier}"


class Staging(ImmutableRecord):
    """A staging order's reviewed facts: what the run sends and where its artifacts go."""

    identifier = models.CharField(max_length=24)
    php_version = models.CharField(max_length=10)
    site_revision = models.PositiveSmallIntegerField(default=3)
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
