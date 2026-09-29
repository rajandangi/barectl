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
    nginx_site_files_status = models.CharField(max_length=12, choices=ObservationOutcome)
    nginx_site_files_source = models.TextField(blank=True)
    nginx_site_files_warning = models.TextField(blank=True)
    php_fpm_pools_status = models.CharField(max_length=12, choices=ObservationOutcome)
    php_fpm_pools_source = models.TextField(blank=True)
    php_fpm_pools_warning = models.TextField(blank=True)

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


class ComponentObservation(models.Model):
    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="components"
    )
    component = models.CharField(max_length=12, choices=WebStackComponent)
    package_status = models.CharField(max_length=12, choices=ObservationOutcome)
    packages = models.TextField(blank=True)
    package_source = models.CharField(max_length=500, blank=True)
    package_warning = models.TextField(blank=True)
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


class NginxSiteObservation(models.Model):
    """docs/ssh-connections.md#nginx-site-file-and-php-fpm-pool-observations"""

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="nginx_site_files"
    )
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=12, choices=ObservationOutcome)
    server_names = models.TextField(blank=True)
    listens = models.TextField(blank=True)
    source = models.CharField(max_length=500)
    warning = models.TextField(blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "name"], name="unique_nginx_site_file_per_snapshot"
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.name} in {self.snapshot}"


class PhpFpmPoolObservation(models.Model):
    """docs/ssh-connections.md#nginx-site-file-and-php-fpm-pool-observations"""

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="php_fpm_pools"
    )
    # The PHP version directory the pool was read from, such as "8.3".
    version = models.CharField(max_length=20)
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=12, choices=ObservationOutcome)
    listen = models.CharField(max_length=200, blank=True)
    source = models.CharField(max_length=500)
    warning = models.TextField(blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            models.UniqueConstraint(
                fields=["snapshot", "version", "name"], name="unique_php_fpm_pool_per_snapshot"
            )
        ]
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.name} {self.version} in {self.snapshot}"
