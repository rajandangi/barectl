"""Discovery attempts recorded in any state and age, for tests that need history.

Tests record attempts through ``record_attempt`` rather than writing attempt rows, so
the rule for which timestamps a state carries lives in one place.
"""

from datetime import timedelta

from django.utils import timezone

from servers.models import Server

from .models import DiscoveryAttempt
from .services import STALE_AFTER

AttemptStatus = DiscoveryAttempt.Status
# Old enough for recovery to treat an active attempt as abandoned.
STALE = STALE_AFTER + timedelta(minutes=1)
_FINISHED = (AttemptStatus.SUCCEEDED, AttemptStatus.FAILED)


def record_attempt(
    target: Server | DiscoveryAttempt,
    status: AttemptStatus = AttemptStatus.QUEUED,
    *,
    age: timedelta = timedelta(),
    failure: str = "",
) -> DiscoveryAttempt:
    """Record an attempt that reached ``status`` ``age`` ago, and return it as stored.

    A server gets a new attempt without a worker task, recorded ``age`` ago. An existing
    attempt, such as one ``request_discovery`` queued with its task, keeps the time it was
    recorded unless it is queued again. Running attempts start ``age`` ago, finished ones
    finish then; a queued attempt has neither time.
    """
    when = timezone.now() - age
    if isinstance(target, Server):
        attempt = DiscoveryAttempt.objects.create(server=target, ssh_alias=target.ssh_alias)
        recorded = True
    else:
        attempt = target
        recorded = status == AttemptStatus.QUEUED
    changes: dict[str, object] = {
        "status": status,
        "failure": failure,
        "finished_at": when if status in _FINISHED else None,
    }
    if status == AttemptStatus.RUNNING:
        changes["started_at"] = when
    elif recorded:
        changes["started_at"] = None
    if recorded:
        # queued_at is set when a row is created; an update makes the recorded time exact.
        changes["queued_at"] = when
    DiscoveryAttempt.objects.filter(pk=attempt.pk).update(**changes)
    attempt.refresh_from_db()
    return attempt
