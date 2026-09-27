from collections.abc import Sequence
from typing import ClassVar, NamedTuple, override

from django.db import models
from django.db.models import Q
from django.db.models.expressions import Combinable

from servers.aliases import ALIAS_MAX_LENGTH
from servers.models import Server


class DiscoveryAttempt(models.Model):
    """One queued run of connection verification and read-only discovery for a server.

    Attempts are kept separately from the server registration and from the snapshots they
    publish, so a failed attempt never replaces earlier observations.
    """

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    ACTIVE: ClassVar[tuple[Status, Status]] = (Status.QUEUED, Status.RUNNING)

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="discovery_attempts")
    # The alias the attempt connects with, recorded when it was queued.
    ssh_alias = models.CharField("SSH alias", max_length=ALIAS_MAX_LENGTH)
    status = models.CharField(max_length=10, choices=Status, default=Status.QUEUED)
    queued_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # Operator-facing explanation of a failure. Never raw exception or remote output.
    failure = models.TextField(blank=True)
    # The verified host key, such as "ssh-ed25519 SHA256:…". Public information.
    host_key = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["-queued_at", "-pk"]
        constraints: ClassVar[list[models.BaseConstraint] | tuple[models.BaseConstraint, ...]] = [
            # Repeated registration or verification requests cannot start competing jobs.
            models.UniqueConstraint(
                fields=["server"],
                condition=Q(status__in=["queued", "running"]),
                name="discovery_one_active_attempt_per_server",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} discovery of {self.ssh_alias}"

    @property
    def is_active(self) -> bool:
        return self.status in self.ACTIVE


class ObservationStatus(models.TextChoices):
    OBSERVED = "observed", "Observed"
    # The file or command exists but the SSH user may not read or run it.
    INACCESSIBLE = "inaccessible", "Inaccessible"
    ABSENT = "absent", "Absent"
    # Present but not in a form Barectl can interpret.
    UNSUPPORTED = "unsupported", "Unsupported"


class CapacityObservation(NamedTuple):
    status: str
    status_label: str
    source: str
    warning: str


class DiscoverySnapshot(models.Model):
    """Observations published by one successful attempt, as they were at collection time."""

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="snapshots")
    attempt = models.OneToOneField(
        DiscoveryAttempt, on_delete=models.CASCADE, related_name="snapshot"
    )
    collected_at = models.DateTimeField()
    os_status = models.CharField(max_length=12, choices=ObservationStatus)
    # The remote file the OS observation was read from.
    os_source = models.CharField(max_length=100, blank=True)
    os_pretty_name = models.CharField(max_length=200, blank=True)
    os_name = models.CharField(max_length=200, blank=True)
    os_id = models.CharField(max_length=100, blank=True)
    os_version_id = models.CharField(max_length=100, blank=True)
    os_warning = models.TextField(blank=True)
    arch_status = models.CharField(max_length=12, choices=ObservationStatus)
    # The machine hardware name reported by uname, such as "x86_64".
    arch_value = models.CharField(max_length=100, blank=True)
    arch_source = models.CharField(max_length=100, blank=True)
    arch_warning = models.TextField(blank=True)
    cpu_status = models.CharField(max_length=12, choices=ObservationStatus)
    # The available processing units reported by nproc. Null unless observed.
    cpu_count = models.PositiveIntegerField(null=True, blank=True)
    cpu_source = models.CharField(max_length=100, blank=True)
    cpu_warning = models.TextField(blank=True)
    memory_status = models.CharField(max_length=12, choices=ObservationStatus)
    # Total memory in bytes, converted from MemTotal in kB. Null unless observed.
    memory_bytes = models.BigIntegerField(null=True, blank=True)
    memory_source = models.CharField(max_length=100, blank=True)
    memory_warning = models.TextField(blank=True)
    filesystem_status = models.CharField(max_length=12, choices=ObservationStatus)
    # Root filesystem capacity in bytes, from df -B1. Null unless observed.
    filesystem_size_bytes = models.BigIntegerField(null=True, blank=True)
    filesystem_avail_bytes = models.BigIntegerField(null=True, blank=True)
    filesystem_source = models.CharField(max_length=100, blank=True)
    filesystem_warning = models.TextField(blank=True)
    # The verdict on the site directory itself, such as /etc/nginx/sites-enabled.
    # Snapshots collected before site observations existed record unsupported with a
    # "not collected" warning, as arch_status does in migration 0002.
    nginx_site_files_status = models.CharField(max_length=12, choices=ObservationStatus)
    nginx_site_files_source = models.CharField(max_length=100, blank=True)
    nginx_site_files_warning = models.TextField(blank=True)
    # The verdict on the PHP configuration tree itself, such as /etc/php.
    php_fpm_pools_status = models.CharField(max_length=12, choices=ObservationStatus)
    php_fpm_pools_source = models.CharField(max_length=100, blank=True)
    php_fpm_pools_warning = models.TextField(blank=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["-collected_at", "-pk"]

    @override
    def __str__(self) -> str:
        return f"Snapshot of {self.server} at {self.collected_at:%Y-%m-%d %H:%M}"

    @property
    def capacity(self) -> list[CapacityObservation]:
        """The capacity observations, in display order."""
        return [
            CapacityObservation(
                self.arch_status,
                self.get_arch_status_display(),
                self.arch_source,
                self.arch_warning,
            ),
            CapacityObservation(
                self.cpu_status, self.get_cpu_status_display(), self.cpu_source, self.cpu_warning
            ),
            CapacityObservation(
                self.memory_status,
                self.get_memory_status_display(),
                self.memory_source,
                self.memory_warning,
            ),
            CapacityObservation(
                self.filesystem_status,
                self.get_filesystem_status_display(),
                self.filesystem_source,
                self.filesystem_warning,
            ),
        ]

    @property
    def service_sources(self) -> list[str]:
        """The distinct commands the service observations were read with, in row order."""
        sources: list[str] = []
        for service in self.components.all():
            for source in (service.package_source, service.service_source):
                if source and source not in sources:
                    sources.append(source)
        return sources


class ServiceComponent(models.TextChoices):
    """The web-stack components Barectl observes, in display order."""

    NGINX = "nginx", "Nginx"
    PHP_FPM = "php-fpm", "PHP-FPM"
    MARIADB = "mariadb", "MariaDB"
    POSTGRESQL = "postgresql", "PostgreSQL"


class ComponentObservation(models.Model):
    """One web-stack component's package versions and systemd service states in a snapshot.

    The package and service observations are separate: a server can report package versions
    from the dpkg database while its service state cannot be read from systemd, and the
    other way around. Each carries its own status, source and warning.
    """

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="components"
    )
    component = models.CharField(max_length=12, choices=ServiceComponent)
    package_status = models.CharField(max_length=12, choices=ObservationStatus)
    # One "name version" line per installed package found in the dpkg database.
    packages = models.TextField(blank=True)
    package_source = models.CharField(max_length=500, blank=True)
    package_warning = models.TextField(blank=True)
    service_status = models.CharField(max_length=12, choices=ObservationStatus)
    # One "unit state" line per systemd unit Barectl queried, such as
    # "nginx.service active (running), enabled".
    units = models.TextField(blank=True)
    service_source = models.CharField(max_length=500, blank=True)
    service_warning = models.TextField(blank=True)

    class Meta:
        # Rows are created in ServiceComponent order, so primary-key order is display order.
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.get_component_display()} in {self.snapshot}"


class NginxSiteObservation(models.Model):
    """One Nginx site configuration file's observed server names and listen addresses.

    The name is the entry in the server's sites-enabled directory. Only the file's server
    blocks' ``server_name`` and ``listen`` values are kept; the rest of the file is never
    stored. A file the SSH user cannot read or that Barectl cannot interpret carries its
    own status and warning.
    """

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="nginx_site_files"
    )
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=12, choices=ObservationStatus)
    # One server name per line, as the file's server blocks declare them.
    server_names = models.TextField(blank=True)
    # One listen address per line, such as "80" or "127.0.0.1:8080".
    listens = models.TextField(blank=True)
    # The remote file the observation was read from.
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
    """One PHP-FPM pool's observed listen address in a snapshot.

    Pools are identified by their configuration section name within one PHP version.
    Only the pool name, its PHP version and its listen address are kept; environment
    values and other directives are never stored.
    """

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="php_fpm_pools"
    )
    # The PHP version directory the pool was read from, such as "8.3".
    version = models.CharField(max_length=20)
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=12, choices=ObservationStatus)
    # Where the pool listens, such as "/run/php/php8.3-fpm.sock" or "127.0.0.1:9000".
    listen = models.CharField(max_length=200, blank=True)
    # The remote file the observation was read from.
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
