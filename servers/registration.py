"""docs/architecture.md#request-and-execution-flow"""

import getpass
import logging
from enum import Enum, auto

from django.conf import settings
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction

from discovery.services import (
    DiscoveryBusy,
    forget_discovery,
    queue_discovery,
    recorded_discovery,
)
from operations.lifecycle import recovers_first
from operations.services import forget_changes, keep_run_audit

from .connections import alias_digest, normalize_address, saved_alias, validate_username
from .models import ConnectionDefinition, Server
from .ssh_config import resolve_alias

logger = logging.getLogger(__name__)


class SaveOutcome(Enum):
    # Saved; the alias did not change, so no connection check was queued.
    SAVED = auto()
    # Saved with a new alias, and a connection check was queued with it.
    QUEUED = auto()
    # Nothing saved: another server was saved with this name or alias meanwhile.
    TAKEN = auto()
    # Nothing saved: an operation with the current alias is active, so the alias must stay.
    BUSY = auto()
    STALE = auto()


class RemovalBlocked(Exception):
    """The server has an active remote operation, so its registration must stay."""


@recovers_first
def save_server(server: Server, *, user: User | None = None) -> SaveOutcome:
    """Save a registration or edit, queueing a connection check when the alias is new.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the edited server;
    an edit only updates, so saving never registers a removed server again.
    """
    editing = server.pk is not None
    try:
        with transaction.atomic():
            stored = Server.objects.get(pk=server.pk) if editing else None
            if stored is not None:
                from operations.lifecycle import active_operation

                if active_operation(stored) is not None:
                    return SaveOutcome.BUSY
            digest = _normalize_edit(server, stored)
            queue = _connection_changed(server, stored, digest)
            if stored is not None and (
                server.connection_revision != stored.connection_revision
                or server.registration_revision != stored.registration_revision
            ):
                return SaveOutcome.STALE
            if queue:
                server.connection_revision += 1
            server.registration_revision += 1
            if not _write_registration(server, stored):
                return SaveOutcome.STALE
            if queue:
                ConnectionDefinition.objects.create(
                    server=server,
                    revision=server.connection_revision,
                    mode=server.connection_mode,
                    alias=server.ssh_alias,
                    address=server.address,
                    username=server.username,
                    port=server.port,
                    alias_config_digest=digest,
                    credential_reference=server.credential_reference,
                    credential_public_key=server.credential_public_key,
                    credential_file_identity=server.credential_file_identity,
                )
                queue_discovery(
                    server,
                    user=user,
                    authority="servers.change_server" if editing else "servers.add_server",
                )
    except IntegrityError:
        return SaveOutcome.TAKEN
    except DiscoveryBusy:
        return SaveOutcome.BUSY
    return SaveOutcome.QUEUED if queue else SaveOutcome.SAVED


def _connection_changed(server: Server, stored: Server | None, digest: str) -> bool:
    if stored is None:
        return True
    previous = ConnectionDefinition.objects.filter(
        server=stored, revision=stored.connection_revision
    ).first()
    fields: tuple[str, ...] = ("ssh_alias", "connection_mode")
    if server.connection_mode in {"agent", "keyfile"}:
        fields += (
            "address",
            "username",
            "port",
            "credential_reference",
            "credential_public_key",
            "credential_file_identity",
        )
    return any(getattr(server, field) != getattr(stored, field) for field in fields) or (
        previous is not None and previous.alias_config_digest != digest
    )


def _normalize_edit(server: Server, stored: Server | None) -> str:
    fields: tuple[str, ...] = ("ssh_alias", "connection_mode")
    if server.connection_mode != "alias":
        fields += (
            "address",
            "username",
            "port",
            "credential_reference",
            "credential_public_key",
            "credential_file_identity",
        )
    if stored is not None and all(
        getattr(server, field) == getattr(stored, field) for field in fields
    ):
        server.address, server.username, server.port = stored.address, stored.username, stored.port
        previous = ConnectionDefinition.objects.filter(
            server=stored, revision=stored.connection_revision
        ).first()
        server.full_clean(validate_unique=False, validate_constraints=False)
        return previous.alias_config_digest if previous else ""
    return _normalize_registration(server)


def _write_registration(server: Server, stored: Server | None) -> bool:
    if stored is None:
        server.save()
        return True
    values = {
        field: getattr(server, field)
        for field in (
            "name",
            "ssh_alias",
            "connection_mode",
            "address",
            "username",
            "port",
            "connection_revision",
            "registration_revision",
            "credential_reference",
            "credential_public_key",
            "credential_file_identity",
        )
    }
    return bool(
        Server.objects.filter(
            pk=server.pk,
            connection_revision=stored.connection_revision,
            registration_revision=stored.registration_revision,
        ).update(**values)
    )


@recovers_first
def remove_server(server: Server) -> None:
    """docs/ssh-connections.md#server-removal"""
    try:
        with transaction.atomic():
            stored = Server.objects.get(pk=server.pk)
            from operations.lifecycle import active_operation

            if (
                stored.connection_revision != server.connection_revision
                or stored.registration_revision != server.registration_revision
                or active_operation(stored) is not None
            ):
                raise RemovalBlocked
            forget_discovery(server)
            forget_changes(server)
            keep_run_audit(server)
            # Deleting through a queryset leaves the instance usable if the commit fails.
            Server.objects.filter(pk=server.pk).delete()
    except IntegrityError:
        # ProtectedError is an IntegrityError, and a concurrently queued operation fails the
        # foreign key check at commit. Either way everything was rolled back.
        raise RemovalBlocked from None
    logger.info("Removed server %s and its local history", server.pk)


def active_matching_registration(server: Server) -> Server | None:
    """An identical submission shares the discovery already queued by its first save."""
    _normalize_registration(server)
    fields = (
        "name",
        "ssh_alias",
        "connection_mode",
        "address",
        "username",
        "port",
        "credential_reference",
        "credential_public_key",
        "credential_file_identity",
    )
    existing = Server.objects.filter(**{field: getattr(server, field) for field in fields}).first()
    if existing is None:
        return None
    from operations.lifecycle import active_operation
    from operations.models import RemoteOperation

    recorded_discovery(existing)
    active = active_operation(existing)
    return (
        existing if active is not None and active.kind == RemoteOperation.Kind.DISCOVERY else None
    )


def _normalize_registration(server: Server) -> str:
    digest = ""
    if server.connection_mode == "alias":
        target = resolve_alias(settings.SSH_CONFIG_PATH, server.ssh_alias)
        server.address = normalize_address(target.hostname)
        server.username = target.user or getpass.getuser()
        server.port = target.port
        digest = alias_digest(target)
    elif server.connection_mode in {"agent", "keyfile"}:
        server.address = normalize_address(server.address)
        validate_username(server.username)
        server.ssh_alias = saved_alias(server.address, server.username, server.port)
    server.full_clean(validate_unique=False, validate_constraints=False)
    return digest
