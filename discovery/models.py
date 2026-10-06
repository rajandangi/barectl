from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models
from django.db.models import Q
from django.db.models.expressions import Combinable

from operations.models import RemoteOperation
from servers.models import Server


class DiscoveryAttempt(RemoteOperation):
    """docs/adr/0004-serialize-remote-operations-in-one-table.md"""

    KIND: ClassVar[str] = RemoteOperation.Kind.DISCOVERY
    # Only finished apply runs outlive their server (a database constraint), so an
    # attempt always has one.
    server: Server  # type: ignore[mutable-override]

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} discovery of {self.ssh_alias}"


class ObservationOutcome(models.TextChoices):
    """Whether an observation produced a finding, as CONTEXT.md defines the outcomes."""

    OBSERVED = "observed", "Observed"
    INACCESSIBLE = "inaccessible", "Inaccessible"
    ABSENT = "absent", "Absent"
    UNSUPPORTED = "unsupported", "Unsupported"


class DiscoverySnapshot(models.Model):
    """docs/adr/0003-store-discovery-snapshots-in-typed-columns.md"""

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="snapshots")
    attempt = models.OneToOneField(
        DiscoveryAttempt, on_delete=models.CASCADE, related_name="snapshot"
    )
    collected_at = models.DateTimeField()
    os_status = models.CharField(max_length=12, choices=ObservationOutcome)
    os_source = models.CharField(max_length=100, blank=True)
    os_pretty_name = models.CharField(max_length=200, blank=True)
    os_name = models.CharField(max_length=200, blank=True)
    os_id = models.CharField(max_length=100, blank=True)
    os_version_id = models.CharField(max_length=100, blank=True)
    os_warning = models.TextField(blank=True)
    arch_status = models.CharField(max_length=12, choices=ObservationOutcome)
    arch_value = models.CharField(max_length=100, blank=True)
    arch_source = models.CharField(max_length=100, blank=True)
    arch_warning = models.TextField(blank=True)
    cpu_status = models.CharField(max_length=12, choices=ObservationOutcome)
    cpu_count = models.PositiveIntegerField(null=True, blank=True)
    cpu_source = models.CharField(max_length=100, blank=True)
    cpu_warning = models.TextField(blank=True)
    memory_status = models.CharField(max_length=12, choices=ObservationOutcome)
    memory_bytes = models.BigIntegerField(null=True, blank=True)
    memory_source = models.CharField(max_length=100, blank=True)
    memory_warning = models.TextField(blank=True)
    filesystem_status = models.CharField(max_length=12, choices=ObservationOutcome)
    filesystem_size_bytes = models.BigIntegerField(null=True, blank=True)
    filesystem_avail_bytes = models.BigIntegerField(null=True, blank=True)
    filesystem_source = models.CharField(max_length=100, blank=True)
    filesystem_warning = models.TextField(blank=True)
    # docs/adr/0001-configuration-observations-depend-on-package-observation.md
    # docs/ssh-connections.md#site-observations
    sites_status = models.CharField(max_length=12, choices=ObservationOutcome)
    sites_source = models.TextField(blank=True)
    sites_warning = models.TextField(blank=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["-collected_at", "-pk"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.CheckConstraint(
                condition=~Q(os_status=ObservationOutcome.ABSENT)
                & ~Q(arch_status=ObservationOutcome.ABSENT)
                & ~Q(cpu_status=ObservationOutcome.ABSENT)
                & ~Q(memory_status=ObservationOutcome.ABSENT)
                & ~Q(filesystem_status=ObservationOutcome.ABSENT),
                name="snapshot_attributes_never_absent",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Snapshot of {self.server} at {self.collected_at:%Y-%m-%d %H:%M}"


class WebStackComponent(models.TextChoices):
    """The web-stack components Barectl observes, in display order."""

    NGINX = "nginx", "Nginx"
    PHP_FPM = "php-fpm", "PHP-FPM"
    MARIADB = "mariadb", "MariaDB"
    POSTGRESQL = "postgresql", "PostgreSQL"
    CERTBOT = "certbot", "Certbot"


class ComponentObservation(models.Model):
    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="components"
    )
    component = models.CharField(max_length=12, choices=WebStackComponent)
    package_status = models.CharField(max_length=12, choices=ObservationOutcome)
    packages = models.TextField(blank=True)
    package_source = models.CharField(max_length=500, blank=True)
    package_warning = models.TextField(blank=True)
    # Whether the installed packages follow the release's bootstrap profile
    # (docs/adr/0015-recognize-only-the-convention.md).
    managed = models.BooleanField(default=True)
    # The packages outside the profile, and PostgreSQL majors or clusters it does not
    # support, each with what to remove or change, one per line.
    deviations = models.TextField(blank=True)
    service_status = models.CharField(max_length=12, choices=ObservationOutcome)
    service_source = models.TextField(blank=True)
    service_warning = models.TextField(blank=True)

    class Meta:
        # Rows are created in WebStackComponent order, so primary-key order is display order.
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.get_component_display()} in {self.snapshot}"


class ServiceUnitObservation(models.Model):
    component = models.ForeignKey(
        ComponentObservation, on_delete=models.CASCADE, related_name="service_units"
    )
    name = models.CharField(max_length=100)
    load_state = models.CharField(max_length=20)
    active_state = models.CharField(max_length=20)
    sub_state = models.CharField(max_length=40)
    unit_file_state = models.CharField(max_length=20, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["component", "name"], name="unique_service_unit_per_component"
            )
        ]
        # Rows are created in query order, so primary-key order is display order.
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.name} in {self.component}"


class SiteStage(models.TextChoices):
    """The released forms of the site's Nginx file (docs/site-conventions.md#tls-convention)."""

    HTTP = "http", "HTTP"
    CHALLENGE = "challenge", "HTTP with challenge route"
    HTTPS = "https", "HTTPS"
    REDIRECT = "redirect", "HTTPS with HTTP redirect"

    @property
    def activated(self) -> bool:
        """Whether the form references the site's certificate lineage over HTTPS."""
        return self in {SiteStage.HTTPS, SiteStage.REDIRECT}


class SiteState(models.TextChoices):
    """The one state a site observation has (docs/adr/0015-recognize-only-the-convention.md)."""

    MANAGED = "managed", "Managed"
    PARTLY_APPLIED = "partly_applied", "Partly applied"
    CHANGED = "changed", "Changed outside Barectl"
    NOT_FOLLOWING = "not_following", "Not following the convention"


class SiteObservation(models.Model):
    """docs/ssh-connections.md#site-observations

    Its view permission alone lets an account read site observations.
    """

    snapshot = models.ForeignKey(DiscoverySnapshot, on_delete=models.CASCADE, related_name="sites")
    # Empty for an enabled file or pool that does not follow the convention.
    identifier = models.CharField(max_length=24, blank=True)
    state = models.CharField(max_length=20, choices=SiteState, default=SiteState.MANAGED)
    outcome = models.CharField(max_length=12, choices=ObservationOutcome)
    # The first differing file, or the file of a blocked item; empty for a managed site.
    file = models.CharField(max_length=200, blank=True)
    # The content Barectl expects at the changed file; empty when there is none.
    expected = models.TextField(blank=True)
    # The convention resources that are absent, one path per line.
    missing = models.TextField(blank=True)
    # Values read from the site's own configuration and account; empty when not read.
    server_names = models.TextField(blank=True)
    php_version = models.CharField(max_length=20, blank=True)
    uid = models.PositiveIntegerField(null=True, blank=True)
    gid = models.PositiveIntegerField(null=True, blank=True)
    home = models.CharField(max_length=200, blank=True)
    shell = models.CharField(max_length=200, blank=True)
    # The site file's observed form and the certificate lineage it references.
    stage = models.CharField(max_length=10, choices=SiteStage, default=SiteStage.HTTP)
    certificate_reference = models.CharField(max_length=200, blank=True, default="")
    certificate_key_reference = models.CharField(max_length=200, blank=True, default="")

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "identifier", "file"], name="unique_site_per_snapshot"
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"Site {self.identifier or self.file} in {self.snapshot}"


class FileType(models.TextChoices):
    FILE = "file", "Regular file"
    DIRECTORY = "directory", "Directory"
    SYMLINK = "symlink", "Symbolic link"
    SOCKET = "socket", "Socket"
    OTHER = "other", "Other file type"


class DatabaseEngine(models.TextChoices):
    MARIADB = "mariadb", "MariaDB"
    POSTGRESQL = "postgresql", "PostgreSQL"


class SiteDatabaseObservation(models.Model):
    """docs/ssh-connections.md#site-database-observations

    A site observation without one was collected before database bindings were observed.
    """

    site = models.OneToOneField(SiteObservation, on_delete=models.CASCADE, related_name="database")
    # The engine holding the site's principal or database; empty when none was observed.
    engine = models.CharField(max_length=12, choices=DatabaseEngine, blank=True)
    status = models.CharField(max_length=12, choices=ObservationOutcome)
    # Observed, and the binding docs/site-conventions.md#database-convention describes.
    conforms = models.BooleanField()
    # Whether an ordered prefix of the convention's statements took effect.
    partial = models.BooleanField(default=False)
    principal = models.CharField(max_length=100, blank=True)
    database = models.CharField(max_length=100, blank=True)
    # The authentication method, peer for the distribution's pg_hba.conf rules.
    authentication = models.CharField(max_length=40, blank=True)
    privileges = models.TextField(blank=True)
    character_set = models.CharField(max_length=40, blank=True)
    collation = models.CharField(max_length=100, blank=True)
    owner = models.CharField(max_length=100, blank=True)
    source = models.TextField()
    warning = models.TextField(blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.CheckConstraint(
                condition=Q(conforms=False) | Q(status=ObservationOutcome.OBSERVED),
                name="only_observed_databases_conform",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Database of {self.site}"


class SiteCertificateObservation(models.Model):
    """The public facts of an activated site's certificate.

    Empty when the snapshot was collected before TLS stages were observed.
    """

    site = models.OneToOneField(
        SiteObservation, on_delete=models.CASCADE, related_name="certificate"
    )
    # The certificate lineage's public facts, or why they could not be read.
    status = models.CharField(max_length=12, choices=ObservationOutcome)
    # Observed, and the site's names and renewal configuration as the convention requires.
    conforms = models.BooleanField()
    issuer = models.CharField(max_length=200, blank=True)
    not_before = models.CharField(max_length=40, blank=True)
    not_after = models.CharField(max_length=40, blank=True)
    serial = models.CharField(max_length=100, blank=True)
    # Lower-case hexadecimal SHA-256 of the DER certificate, without colons.
    fingerprint = models.CharField(max_length=64, blank=True)
    # The DNS names the certificate's subjectAltName extension holds, one per line.
    names = models.TextField(blank=True)
    # The served fingerprint per site name, as "name fingerprint", one per line; an empty
    # fingerprint means the TLS probe could not read the served certificate.
    served = models.TextField(blank=True)
    # present, absent or inaccessible, as the renewal configuration's existence was read.
    renewal = models.CharField(max_length=12, blank=True)
    source = models.TextField()
    warning = models.TextField(blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.CheckConstraint(
                condition=Q(conforms=False) | Q(status=ObservationOutcome.OBSERVED),
                name="only_observed_certificates_conform",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"Certificate of {self.site}"
