"""Registering a managed server, changing its alias, and server removal.

Views call ``save_server`` to register or edit a server, and ``remove_server`` to remove
it; they turn the outcomes into messages and form errors. The removal page presents
``discovery.services.recorded_discovery`` and ``bootstrap.services.recorded_plans``.
Remote operations are changed only through their kinds' services: saving a new alias
queues a discovery attempt, and removal forgets the server's discovery history and its
plan preparations with their plans.
"""

import logging
from enum import Enum, auto

from django.db import DatabaseError, IntegrityError, transaction

from bootstrap.services import forget_plans
from discovery.services import (
    DiscoveryBusy,
    forget_discovery,
    queue_discovery,
)

from .models import Server

logger = logging.getLogger(__name__)


class SaveOutcome(Enum):
    """What ``save_server`` did with a registration or edit."""

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


def _stored_alias(server: Server) -> str:
    """The alias saved for an edited server.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    stored = Server.objects.filter(pk=server.pk).values_list("ssh_alias", flat=True).first()
    if stored is None:
        raise Server.DoesNotExist
    return stored


def save_server(server: Server) -> SaveOutcome:
    """Save a registration or edit, queueing a connection check when the alias is new.

    The alias is new for a registration, or when it differs from the saved one. The server
    and its attempt are saved together or not at all. Raises ``Server.DoesNotExist`` when
    a concurrent request removed the edited server; an edit only updates, so saving never
    registers a removed server again.
    """
    editing = server.pk is not None
    try:
        with transaction.atomic():
            queue = not editing or server.ssh_alias != _stored_alias(server)
            server.save(force_update=editing)
            if queue:
                queue_discovery(server)
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
    """Delete a registration with its local history; raise ``RemovalBlocked``.

    Only Barectl's own records are deleted. Nothing connects to the server, and the
    controller's SSH configuration, keys and known_hosts are never touched. The finished
    attempts and the snapshots they published, and the finished plan preparations with
    their plans, are deleted first. An active remote operation protects its server, so
    the database refuses the removal. The database also arbitrates an operation created
    after that: the server row cannot be deleted while any operation references it.
    SQLite's immediate transactions serialize removal with concurrent requests, so one of
    them sees the other's committed result.
    """
    try:
        with transaction.atomic():
            forget_discovery(server)
            forget_plans(server)
            # Deleting through a queryset leaves the instance usable if the commit fails.
            Server.objects.filter(pk=server.pk).delete()
    except IntegrityError:
        # ProtectedError is an IntegrityError, and a concurrently queued operation fails the
        # foreign key check at commit. Either way everything was rolled back.
        raise RemovalBlocked from None
    logger.info("Removed server %s and its local history", server.pk)
