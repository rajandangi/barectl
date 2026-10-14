"""docs/architecture.md#request-and-execution-flow"""

import getpass
import logging
from enum import Enum, auto

from django.conf import settings
from django.contrib.auth.models import User
from django.db import DatabaseError, IntegrityError, transaction

from bootstrap.apply import keep_apply_audit
from bootstrap.services import forget_plans
from discovery.services import (
    DiscoveryBusy,
    forget_discovery,
    queue_discovery,
    recorded_discovery,
)
from operations.services import forget_changes, keep_run_audit
from tls.installation import detach_installations

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


class RemovalBlocked(Exception):
    """The server has an active remote operation, so its registration must stay."""


def save_server(server: Server, *, user: User | None = None) -> SaveOutcome:
    """Save a registration or edit, queueing a connection check when the alias is new.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the edited server;
    an edit only updates, so saving never registers a removed server again.
    """
    editing = server.pk is not None
    digest = _normalize_registration(server)
    try:
        with transaction.atomic():
            stored = Server.objects.get(pk=server.pk) if editing else None
            previous = (
                ConnectionDefinition.objects.filter(
                    server=stored, revision=stored.connection_revision
                ).first()
                if stored is not None
                else None
            )
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
            queue = (
                stored is None
                or any(getattr(server, field) != getattr(stored, field) for field in fields)
                or (previous is not None and previous.alias_config_digest != digest)
            )
            if stored is not None and server.connection_revision != stored.connection_revision:
                return SaveOutcome.BUSY
            if queue:
                server.connection_revision += 1
            server.save(force_update=editing)
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
    except DatabaseError:
        if editing and not Server.objects.filter(pk=server.pk).exists():
            raise Server.DoesNotExist from None
        raise
    return SaveOutcome.QUEUED if queue else SaveOutcome.SAVED


def remove_server(server: Server) -> None:
    """docs/ssh-connections.md#server-removal"""
    try:
        with transaction.atomic():
            detach_installations(server)
            forget_discovery(server)
            forget_plans(server)
            keep_apply_audit(server)
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
