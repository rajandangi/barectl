from collections.abc import Sequence
from typing import ClassVar, TypeAlias, override

from django.db import models
from django.db.models import Q
from django.db.models.expressions import Combinable

from servers.aliases import ALIAS_MAX_LENGTH
from servers.models import Server


class _AttemptStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"


# Module level, so the one-active-attempt constraint in Meta can read the same statuses.
_ACTIVE = (_AttemptStatus.QUEUED, _AttemptStatus.RUNNING)


class DiscoveryAttempt(models.Model):
    """One queued run of connection verification and read-only discovery for a server.

    Attempts are kept separately from the server registration and from the snapshots they
    publish, so a failed attempt never replaces earlier observations.
    """

    # A plain alias rather than a type statement, which would hide the members at runtime.
    Status: TypeAlias = _AttemptStatus  # noqa: UP040
    ACTIVE: ClassVar[tuple[_AttemptStatus, _AttemptStatus]] = _ACTIVE

    # Removal deletes a server's attempts before the server. Protecting the server makes the
    # database refuse to delete it while any attempt remains, including one queued by a
    # concurrent request after removal checked for active attempts.
    server = models.ForeignKey(Server, on_delete=models.PROTECT, related_name="discovery_attempts")
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
                condition=Q(status__in=_ACTIVE),
                name="discovery_one_active_attempt_per_server",
            ),
        ]

    @override
    def __str__(self) -> str:
        return f"{self.get_status_display()} discovery of {self.ssh_alias}"

    @property
    def is_active(self) -> bool:
        return self.status in self.ACTIVE


class ObservationOutcome(models.TextChoices):
    """Whether an observation produced a finding, as CONTEXT.md defines the outcomes."""

    # Barectl read the fact and interpreted it.
    OBSERVED = "observed", "Observed"
    # The SSH user's permissions refused the inspection. Barectl never escalates.
    INACCESSIBLE = "inaccessible", "Inaccessible"
    # A positive finding: the supported inspection worked and showed the thing does not
    # exist. A missing inspection tool never makes something absent.
    ABSENT = "absent", "Absent"
    # No finding: what Barectl read is not in a form it interprets, or its way of
    # inspecting is unavailable. It says nothing about whether the thing exists.
    UNSUPPORTED = "unsupported", "Unsupported"


class DiscoverySnapshot(models.Model):
    """Observations published by one successful attempt, as they were at collection time."""

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="snapshots")
    attempt = models.OneToOneField(
        DiscoveryAttempt, on_delete=models.CASCADE, related_name="snapshot"
    )
    collected_at = models.DateTimeField()
    os_status = models.CharField(max_length=12, choices=ObservationOutcome)
    # The remote file the OS observation was read from.
    os_source = models.CharField(max_length=100, blank=True)
    os_pretty_name = models.CharField(max_length=200, blank=True)
    os_name = models.CharField(max_length=200, blank=True)
    os_id = models.CharField(max_length=100, blank=True)
    os_version_id = models.CharField(max_length=100, blank=True)
    os_warning = models.TextField(blank=True)
    arch_status = models.CharField(max_length=12, choices=ObservationOutcome)
    # The machine hardware name reported by uname, such as "x86_64".
    arch_value = models.CharField(max_length=100, blank=True)
    arch_source = models.CharField(max_length=100, blank=True)
    arch_warning = models.TextField(blank=True)
    cpu_status = models.CharField(max_length=12, choices=ObservationOutcome)
    # The available processing units reported by nproc. Null unless observed.
    cpu_count = models.PositiveIntegerField(null=True, blank=True)
    cpu_source = models.CharField(max_length=100, blank=True)
    cpu_warning = models.TextField(blank=True)
    memory_status = models.CharField(max_length=12, choices=ObservationOutcome)
    # Total memory in bytes, converted from MemTotal in kB. Null unless observed.
    memory_bytes = models.BigIntegerField(null=True, blank=True)
    memory_source = models.CharField(max_length=100, blank=True)
    memory_warning = models.TextField(blank=True)
    filesystem_status = models.CharField(max_length=12, choices=ObservationOutcome)
    # Root filesystem capacity in bytes, from df -B1. Null unless observed.
    filesystem_size_bytes = models.BigIntegerField(null=True, blank=True)
    filesystem_avail_bytes = models.BigIntegerField(null=True, blank=True)
    filesystem_source = models.CharField(max_length=100, blank=True)
    filesystem_warning = models.TextField(blank=True)
    # The outcome for the Nginx site file directory itself, such as /etc/nginx/sites-enabled.
    # Without an installed Nginx package it is the package observation's, and so is the source.
    # A source holds the reads that decided the outcome, one per line.
    nginx_site_files_status = models.CharField(max_length=12, choices=ObservationOutcome)
    nginx_site_files_source = models.TextField(blank=True)
    nginx_site_files_warning = models.TextField(blank=True)
    # The outcome for the PHP-FPM pools as a whole. Without an installed PHP-FPM package it is
    # the package observation's, and so is the source.
    php_fpm_pools_status = models.CharField(max_length=12, choices=ObservationOutcome)
    php_fpm_pools_source = models.TextField(blank=True)
    php_fpm_pools_warning = models.TextField(blank=True)

    class Meta:
        ordering: ClassVar[Sequence[str | Combinable]] = ["-collected_at", "-pk"]
        # Every server has an operating system, an architecture, CPUs, memory and a root
        # filesystem. Their observations are never absent, only uninspected.
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
    """One web-stack component's package versions and systemd service states in a snapshot.

    The package and service observations are separate: a server can report package versions
    from the dpkg database while its service state cannot be read from systemd, and the
    other way around. Each carries its own status, source and warning.
    """

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="components"
    )
    component = models.CharField(max_length=12, choices=WebStackComponent)
    package_status = models.CharField(max_length=12, choices=ObservationOutcome)
    # One "name version" line per installed package found in the dpkg database.
    packages = models.TextField(blank=True)
    package_source = models.CharField(max_length=500, blank=True)
    package_warning = models.TextField(blank=True)
    service_status = models.CharField(max_length=12, choices=ObservationOutcome)
    # The commands the service observation was read with, one per line.
    service_source = models.TextField(blank=True)
    service_warning = models.TextField(blank=True)

    class Meta:
        # Rows are created in WebStackComponent order, so primary-key order is display order.
        ordering: ClassVar[Sequence[str | Combinable]] = ["pk"]

    @override
    def __str__(self) -> str:
        return f"{self.get_component_display()} in {self.snapshot}"


class ServiceUnitObservation(models.Model):
    """One service unit's states in a component's service observation.

    The states are systemd's own tokens, such as "loaded", "active", "running" and
    "enabled". A unit without a unit file has an empty unit-file state.
    """

    component = models.ForeignKey(
        ComponentObservation, on_delete=models.CASCADE, related_name="service_units"
    )
    # The unit's name, such as "nginx.service".
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
    """One Nginx site file's observed server names and listen addresses.

    The name is the entry in the server's sites-enabled directory. Only the file's server
    blocks' ``server_name`` and ``listen`` values are kept; the rest of the file is never
    stored. A file the SSH user cannot read or that Barectl cannot interpret carries its
    own status and warning.
    """

    snapshot = models.ForeignKey(
        DiscoverySnapshot, on_delete=models.CASCADE, related_name="nginx_site_files"
    )
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=12, choices=ObservationOutcome)
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
    status = models.CharField(max_length=12, choices=ObservationOutcome)
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
