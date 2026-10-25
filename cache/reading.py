"""Read one site's cache metrics on demand, through the worker and ``RemoteShell``.

docs/target-architecture.md's Volatile cache reading, #392. The read runs a fixed
``valkey-cli INFO`` as the site's own account under the shared read lock, so it proves what
the site itself can see. Only the numbers are kept, on the request row, and the next
reading replaces them; opening a page queues nothing.
"""

import re
import shlex
from datetime import timedelta
from typing import Final

from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone

from discovery.presentation import VIEW_SITES
from discovery.root_read import run_root
from discovery.ssh import connect_operation
from operations import lifecycle
from operations.lifecycle import OperationRefused, recovers_first
from operations.models import RemoteOperation
from servers.models import Server

from . import convention
from .models import CacheReading

READ_PERMISSIONS: Final = ("servers.view_server", VIEW_SITES)
INTERRUPTED_FAILURE: Final = (
    "The cache reading worker stopped before finishing this request. Request another reading."
)
UNEXPECTED_FAILURE: Final = (
    "The cache reading stopped because of an unexpected error. Barectl did not record the "
    "error details, which could include remote output. Request another reading."
)
STALE_AFTER: Final = timedelta(minutes=5)
READING_LIFETIME: Final = timedelta(hours=24)
_CLI: Final = "/usr/bin/valkey-cli"
_DIGITS: Final = re.compile(r"[0-9]+")
_STATES: Final = frozenset({"running", "stopped", "unreadable"})


def read_command(identifier: str) -> str:
    """The fixed read of one site's cache, as that site's own account."""
    paths = convention.instance_paths(identifier)
    argv = [
        "/usr/sbin/runuser",
        "-u",
        "s" + identifier,
        "--",
        _CLI,
        "-s",
        paths.socket,
        "INFO",
    ]
    from operations import native

    return "sh -c " + shlex.quote(
        "; ".join([*native.read_lock_steps(), "exec " + shlex.join(argv)])
    )


def parse_info(text: str) -> dict[str, int] | None:
    """The four numbers the Overview shows, or ``None`` when the answer is not INFO."""
    wanted = ("used_memory", "maxmemory", "evicted_keys", "connected_clients")
    values: dict[str, int] = {}
    for line in text.splitlines():
        name, separator, raw = line.partition(":")
        if not separator or name not in wanted or name in values:
            continue
        value = raw.strip()
        if _DIGITS.fullmatch(value) is None:
            return None
        values[name] = int(value)
    return values if values.keys() == set(wanted) else None


def _authorized(reading: CacheReading) -> None:
    user = (
        User.objects.filter(pk=reading.requested_by_id).first() if reading.requested_by_id else None
    )
    if user is None or not user.is_active or not user.has_perms(READ_PERMISSIONS):
        raise OperationRefused("Permission to read this site's cache is no longer available.")


def _read(reading: CacheReading) -> None:
    _authorized(reading)
    value: dict[str, object]
    with connect_operation(reading) as shell:
        result = run_root(shell, read_command(reading.identifier))
    if result.exit_status != 0:
        # The private server answered no INFO: it is stopped, gone, or refusing this
        # account. All three mean the site has no usable cache.
        value = {"state": "stopped"}
    elif result.truncated:
        value = {"state": "unreadable"}
    else:
        numbers = parse_info(result.stdout)
        value = {"state": "running", **numbers} if numbers is not None else {"state": "unreadable"}
    now = timezone.now()
    with transaction.atomic():
        # ``succeed`` updates the base operation table, so the reading's own fields are
        # written only after it proves this worker still owns the operation.
        if not lifecycle.succeed(reading.pk, now):
            return
        CacheReading.objects.filter(pk=reading.pk).update(reading=value, reading_at=now)


lifecycle.register(
    CacheReading,
    _read,
    interrupted=INTERRUPTED_FAILURE,
    unexpected=UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
)


@recovers_first
def latest_reading(server: Server, identifier: str) -> dict[str, object] | None:
    """The newest finished reading of this site's cache, if it is still fresh."""
    row = (
        CacheReading.objects.filter(
            server=server, identifier=identifier, status=RemoteOperation.Status.SUCCEEDED
        )
        .exclude(reading={})
        .order_by("-finished_at", "-pk")
        .first()
    )
    if row is None or row.reading_at is None:
        return None
    if timezone.now() - row.reading_at > READING_LIFETIME:
        return None
    state = row.reading.get("state")
    if state not in _STATES:
        return None
    return dict(row.reading)


@recovers_first
def request_reading(server: Server, user: User, identifier: str) -> CacheReading | None:
    """Queue one reading; ``None`` when another operation holds the server."""
    convention.instance_paths(identifier)
    if not user.has_perms(READ_PERMISSIONS):
        raise OperationRefused("Your account may not read this site's cache.")
    CacheReading.objects.filter(server=server, identifier=identifier).exclude(
        status__in=RemoteOperation.ACTIVE
    ).delete()
    try:
        return lifecycle.queue(CacheReading, server, identifier=identifier, requested_by=user)
    except lifecycle.OperationBusy:
        return None
