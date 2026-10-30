"""Typed discovery records of a server's security checks (ADR 0003, Phase E #302).

One row per discovery snapshot holds the scalar evidence each check reads; rules,
listeners and pending updates are child rows. Nothing here is a score: an empty or
unreadable observation stays explicit.
"""

from collections.abc import Sequence
from typing import ClassVar, override

from django.db import models


class SecurityObservation(models.Model):
    """The checks a discovery attempt read, with each check's own outcome."""

    snapshot = models.OneToOneField(
        "discovery.DiscoverySnapshot", on_delete=models.CASCADE, related_name="security"
    )
    source = models.TextField(blank=True)
    firewall_status = models.CharField(max_length=12)
    firewall_source = models.TextField(blank=True)
    firewall_warning = models.TextField(blank=True)
    listeners_status = models.CharField(max_length=12)
    listeners_source = models.TextField(blank=True)
    listeners_warning = models.TextField(blank=True)
    ssh_status = models.CharField(max_length=12)
    ssh_source = models.TextField(blank=True)
    ssh_warning = models.TextField(blank=True)
    auto_updates_status = models.CharField(max_length=12)
    auto_updates_source = models.TextField(blank=True)
    auto_updates_warning = models.TextField(blank=True)
    updates_status = models.CharField(max_length=12)
    updates_source = models.TextField(blank=True)
    updates_warning = models.TextField(blank=True)
    restart_status = models.CharField(max_length=12)
    restart_source = models.TextField(blank=True)
    restart_warning = models.TextField(blank=True)
    # Firewall evidence.
    ufw_installed = models.BooleanField(default=False)
    ufw_enabled = models.BooleanField(null=True, blank=True)
    default_incoming = models.CharField(max_length=20, blank=True)
    default_outgoing = models.CharField(max_length=20, blank=True)
    default_routed = models.CharField(max_length=20, blank=True)
    ipv6 = models.BooleanField(null=True, blank=True)
    logging = models.CharField(max_length=20, blank=True)
    outside = models.TextField(blank=True)
    firewall_conffiles_intact = models.BooleanField(null=True, blank=True)
    # SSH sign-in evidence.
    password_authentication = models.CharField(max_length=20, blank=True)
    keyboard_interactive = models.CharField(max_length=20, blank=True)
    permit_root_login = models.CharField(max_length=40, blank=True)
    ssh_ports = models.TextField(blank=True)
    socket_ports = models.TextField(blank=True)
    accounts_without_keys = models.TextField(blank=True)
    per_source_penalties = models.CharField(max_length=20, blank=True)
    # Automatic security updates.
    auto_updates_enabled = models.BooleanField(null=True, blank=True)
    list_update_timer = models.CharField(max_length=20, blank=True)
    upgrade_timer = models.CharField(max_length=20, blank=True)
    automatic_reboot = models.BooleanField(null=True, blank=True)
    allowed_origins = models.TextField(blank=True)
    last_upgrade = models.TextField(blank=True)
    conffile_matches = models.BooleanField(null=True, blank=True)
    newest_log_age = models.BigIntegerField(null=True, blank=True)
    # Ubuntu updates.
    list_age_seconds = models.BigIntegerField(null=True, blank=True)
    # Restart needed.
    restart_required = models.BooleanField(null=True, blank=True)
    restart_packages = models.TextField(blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"Security checks of snapshot {self.snapshot_id}"


class SecurityRule(models.Model):
    """One firewall rule, adopted or outside the supported grammar."""

    KIND = (("standard", "Standard"), ("operator", "Operator"), ("outside", "Outside"))
    security = models.ForeignKey(
        SecurityObservation, on_delete=models.CASCADE, related_name="rules"
    )
    kind = models.CharField(max_length=10, choices=KIND)
    line = models.TextField()
    action = models.CharField(max_length=10, blank=True)
    protocol = models.CharField(max_length=5, blank=True)
    ports = models.CharField(max_length=20, blank=True)
    network = models.CharField(max_length=60, blank=True)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return self.line


class SecurityListener(models.Model):
    """One socket listener, and whether it is part of the expected public set."""

    security = models.ForeignKey(
        SecurityObservation, on_delete=models.CASCADE, related_name="listeners"
    )
    address = models.CharField(max_length=80)
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=5)
    process = models.CharField(max_length=80, blank=True)
    public = models.BooleanField(default=False)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"{self.process} on {self.address}:{self.port}/{self.protocol}"


class SecurityPendingUpdate(models.Model):
    """One waiting Ubuntu package update and how APT classifies it."""

    CLASSIFICATION = (
        ("security", "Security"),
        ("other", "Other"),
        ("phased", "Phased"),
        ("held", "Held"),
        ("blocked", "Blocked"),
    )
    security = models.ForeignKey(
        SecurityObservation, on_delete=models.CASCADE, related_name="pending_updates"
    )
    name = models.CharField(max_length=80)
    installed = models.CharField(max_length=80, blank=True)
    candidate = models.CharField(max_length=80, blank=True)
    archive = models.CharField(max_length=200, blank=True)
    classification = models.CharField(max_length=10, choices=CLASSIFICATION)

    class Meta:
        default_permissions: ClassVar[Sequence[str]] = ()

    @override
    def __str__(self) -> str:
        return f"{self.classification} update of {self.name}"
