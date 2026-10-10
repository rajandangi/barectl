"""docs/architecture.md#request-and-execution-flow"""

import logging
from enum import Enum, auto

from django.db import DatabaseError, IntegrityError, transaction

from bootstrap.apply import keep_apply_audit
from bootstrap.services import forget_plans
from discovery.services import (
    DiscoveryBusy,
    forget_discovery,
    queue_discovery,
)
from hosting.creation import detach_creations
from tls.installation import detach_installations

from .models import Server

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


def _stored_alias(server: Server) -> str:
    stored = Server.objects.filter(pk=server.pk).values_list("ssh_alias", flat=True).first()
    if stored is None:
        raise Server.DoesNotExist
    return stored


def save_server(server: Server) -> SaveOutcome:
    """Save a registration or edit, queueing a connection check when the alias is new.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the edited server;
    an edit only updates, so saving never registers a removed server again.
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
    """docs/ssh-connections.md#server-removal"""
    try:
        with transaction.atomic():
            detach_creations(server)
            detach_installations(server)
            forget_discovery(server)
            forget_plans(server)
            keep_apply_audit(server)
            # Deleting through a queryset leaves the instance usable if the commit fails.
            Server.objects.filter(pk=server.pk).delete()
    except IntegrityError:
        # ProtectedError is an IntegrityError, and a concurrently queued operation fails the
        # foreign key check at commit. Either way everything was rolled back.
        raise RemovalBlocked from None
    logger.info("Removed server %s and its local history", server.pk)
