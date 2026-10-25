from collections.abc import Sequence
from typing import ClassVar, override

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.db.models.expressions import Combinable

from operations.models import RemoteOperation
from servers.models import Server


class DiscoveryAttempt(RemoteOperation):
    """docs/adr/0004-serialize-remote-operations-in-one-table.md"""

    KIND: ClassVar[str] = RemoteOperation.Kind.DISCOVERY
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    authority = models.CharField(max_length=80, blank=True)
    expected_host_key = models.TextField(blank=True)
    challenge_key_type = models.CharField(max_length=80, blank=True)
    challenge_key_blob = models.TextField(blank=True)
    challenge_fingerprint = models.CharField(max_length=80, blank=True)
    challenge_address = models.CharField(max_length=253, blank=True)
    challenge_port = models.PositiveIntegerField(null=True, blank=True)
    # Only finished apply runs outlive their server (a database constraint), so an
    # attempt always has one.
    server: Server  # type: ignore[mutable-override]

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} discovery of {self.ssh_alias}"


class ObservationOutcome(models.TextChoices):
    """Whether an observation produced a finding, as GLOSSARY.md defines the outcomes."""

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
    # The Laravel (and plain) release inventory, read from the site layout.
    releases_status = models.CharField(
        max_length=12, choices=ObservationOutcome, default=ObservationOutcome.ABSENT
    )
    releases_source = models.TextField(blank=True, default="")
    releases_warning = models.TextField(blank=True, default="")
    # Keys and server-computed digests of each site's private settings file.
    settings_status = models.CharField(
        max_length=12, choices=ObservationOutcome, default=ObservationOutcome.ABSENT
    )
    settings_source = models.TextField(blank=True, default="")
    settings_warning = models.TextField(blank=True, default="")
    # Each WordPress site's scheduled work and its last result (Phase C #357).
    automation_status = models.CharField(
        max_length=12, choices=ObservationOutcome, default=ObservationOutcome.ABSENT
    )
    automation_source = models.TextField(blank=True, default="")
    automation_warning = models.TextField(blank=True, default="")
    # Each Laravel site's queue-worker definition and state (Phase C #266).
    workers_status = models.CharField(
        max_length=12, choices=ObservationOutcome, default=ObservationOutcome.ABSENT
    )
    workers_source = models.TextField(blank=True, default="")
    workers_warning = models.TextField(blank=True, default="")
    host_standing = models.CharField(max_length=32, blank=True)
    host_standing_reasons = models.TextField(blank=True)
    host_standing_warnings = models.TextField(blank=True)
    host_foundation = models.TextField(blank=True)
    host_evidence = models.TextField(blank=True)
    host_profiles = models.TextField(blank=True)
    # Caddy's optional certificate contact email, read from the main configuration.
    certificate_email = models.CharField(max_length=254, blank=True, default="")
    certificate_email_state = models.CharField(max_length=12, blank=True, default="")
    runtime_warning = models.TextField(blank=True)
    default_runtime_observed = models.BooleanField(default=False)
    default_php = models.CharField(max_length=16, blank=True)
    default_node = models.CharField(max_length=16, blank=True)
    default_php_problem = models.TextField(blank=True)
    default_node_problem = models.TextField(blank=True)
    default_php_choices = models.TextField(blank=True)
    default_node_choices = models.TextField(blank=True)

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
    VALKEY = "valkey", "Valkey"


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


class SiteState(models.TextChoices):
    """The one state a site observation has (docs/adr/0015-recognize-only-the-convention.md)."""

    MANAGED = "managed", "Managed"
    PARTLY_APPLIED = "partly_applied", "Partly applied"
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
    # The convention resources that are absent, one path per line.
    missing = models.TextField(blank=True)
    # Values read from the site's own configuration and account; empty when not read.
    server_names = models.TextField(blank=True)
    php_version = models.CharField(max_length=20, blank=True)
    node_runtime = models.CharField(max_length=16, blank=True)
    # Whether Caddy serves the site over HTTPS, and its certificate evidence (docs/tls.md).
    https = models.BooleanField(default=False)
    # The path Barectl checks after a change (docs/sites.md#readiness).
    readiness = models.CharField(max_length=200, default="/")
    # The pool's supported operator-tunable settings (docs/site-conventions.md).
    pool_process_manager = models.CharField(max_length=10, blank=True)
    pool_max_children = models.PositiveSmallIntegerField(null=True, blank=True)
    pool_start_servers = models.PositiveSmallIntegerField(null=True, blank=True)
    pool_min_spare_servers = models.PositiveSmallIntegerField(null=True, blank=True)
    pool_max_spare_servers = models.PositiveSmallIntegerField(null=True, blank=True)
    pool_process_idle_timeout = models.PositiveSmallIntegerField(null=True, blank=True)
    pool_slowlog_timeout = models.PositiveSmallIntegerField(null=True, blank=True)
    pool_terminate_timeout = models.PositiveSmallIntegerField(null=True, blank=True)
    pool_memory_limit = models.PositiveSmallIntegerField(null=True, blank=True)
    pool_upload_max_filesize = models.PositiveSmallIntegerField(null=True, blank=True)
    pool_post_max_size = models.PositiveSmallIntegerField(null=True, blank=True)
    certificate_state = models.CharField(max_length=16, blank=True)
    certificate_issuer = models.CharField(max_length=200, blank=True)
    certificate_not_after = models.BigIntegerField(default=0)
    certificate_error = models.TextField(blank=True)
    certificate_names = models.TextField(blank=True)
    uid = models.PositiveIntegerField(null=True, blank=True)
    gid = models.PositiveIntegerField(null=True, blank=True)
    home = models.CharField(max_length=200, blank=True)
    shell = models.CharField(max_length=200, blank=True)
    application = models.CharField(max_length=20, default="plain")
    application_version = models.CharField(max_length=40, blank=True)
    application_problem = models.TextField(blank=True)
    # The supported state of the site's root-owned logrotate file (Phase C #389).
    log_rotation = models.CharField(max_length=12, blank=True)

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


class ReleaseObservation(models.Model):
    """One retained application release under a site's release layout."""

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="releases"
    )
    identifier = models.CharField(max_length=24)
    name = models.CharField(max_length=64)
    commit = models.CharField(max_length=40, blank=True)
    created = models.BigIntegerField(default=0)
    state = models.CharField(max_length=20, choices=SiteState, default=SiteState.MANAGED)
    current = models.BooleanField(default=False)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "identifier", "name"],
                name="unique_release_per_snapshot",
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"Release {self.name} of {self.identifier} in {self.snapshot}"


class SettingObservation(models.Model):
    """One key of a site's private settings file, with its server-computed digest."""

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="settings"
    )
    identifier = models.CharField(max_length=24)
    application = models.CharField(max_length=16)
    name = models.CharField(max_length=64)
    digest = models.CharField(max_length=64)
    # Present only for a fixed non-secret key; empty for every secret.
    value = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "identifier", "application", "name"],
                name="unique_setting_per_snapshot",
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.application} {self.name} of {self.identifier} in {self.snapshot}"


class RuntimeObservation(models.Model):
    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="runtimes"
    )
    entry = models.CharField(max_length=32)
    path = models.CharField(max_length=256)
    generation = models.CharField(max_length=256)
    version = models.CharField(max_length=64)
    extensions = models.TextField(blank=True)
    master_state = models.CharField(max_length=32)
    protections = models.TextField(blank=True)
    problem = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()
        ordering: ClassVar[Sequence[str | Combinable]] = ("entry",)

    @override
    def __str__(self) -> str:
        return self.entry
