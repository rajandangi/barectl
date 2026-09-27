"""Registering a managed server, changing its alias, and server removal.

Views call ``save_server`` to register or edit a server, and ``removal_summary`` and
``remove_server`` to remove it; they turn the outcomes into messages and form errors.
Discovery attempts change only through ``discovery.services``: saving a new alias queues
one, and removal forgets the server's discovery history.
"""

import logging
from dataclasses import dataclass
from enum import Enum, auto

from django.db import DatabaseError, IntegrityError, transaction

from discovery.services import (
    DiscoveryBusy,
    forget_discovery,
    has_active_attempt,
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
    # Nothing saved: a check with the current alias is active, so the alias must stay.
    BUSY = auto()


@dataclass(frozen=True)
class RemovalSummary:
    """What removing a server would delete, and whether discovery blocks it now."""

    # A queued or running attempt protects the server from removal.
    busy: bool
    attempt_count: int
    has_snapshot: bool


class RemovalBlocked(Exception):
    """The server has a queued or running attempt, so its registration must stay."""


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


def removal_summary(server: Server) -> RemovalSummary:
    """What ``remove_server`` would delete, after recovering abandoned attempts."""
    busy = has_active_attempt(server)
    return RemovalSummary(
        busy=busy,
        attempt_count=server.discovery_attempts.count(),
        has_snapshot=server.snapshots.exists(),
    )


def remove_server(server: Server) -> None:
    """Delete a registration with its discovery history; raise ``RemovalBlocked``.

    Only Barectl's own records are deleted. Nothing connects to the server, and the
    controller's SSH configuration, keys and known_hosts are never touched. The finished
    attempts and the snapshots they published are deleted first. An active attempt
    protects its server, so the database refuses the removal. The database also
    arbitrates an attempt created after that: the server row cannot be deleted while any
    attempt references it. SQLite's immediate transactions serialize removal with
    concurrent requests, so one of them sees the other's committed result.
    """
    try:
        with transaction.atomic():
            forget_discovery(server)
            # Deleting through a queryset leaves the instance usable if the commit fails.
            Server.objects.filter(pk=server.pk).delete()
    except IntegrityError:
        # ProtectedError is an IntegrityError, and a concurrently queued attempt fails the
        # foreign key check at commit. Either way everything was rolled back.
        raise RemovalBlocked from None
    logger.info("Removed server %s and its discovery history", server.pk)
