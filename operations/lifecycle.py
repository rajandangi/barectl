"""docs/adr/0004-serialize-remote-operations-in-one-table.md"""

import functools
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction
from django.db.models import F, QuerySet
from django.tasks import TaskResultStatus
from django.utils import timezone
from django_tasks_db.models import DBTaskResult, DBTaskResultQuerySet

from discovery.ssh import ConnectionFailed
from servers.models import Server

from .models import RemoteOperation
from .tasks import run_remote_operation

logger = logging.getLogger(__name__)

Status = RemoteOperation.Status


class OperationBusy(Exception):
    def __init__(self, operation: RemoteOperation) -> None:
        super().__init__()
        self.operation = operation


class OperationRefused(Exception):
    """A sanitized, operator-facing reason a step stopped without a result.

    Steps raise it for reasons they establish themselves, such as an account that lost its
    permission before the worker ran; the message is recorded as the failure.
    """


@dataclass(frozen=True)
class _Policy:
    # Loads the claimed operation's details and does the kind's work.
    step: Callable[[int], None]
    # The failure recorded when the worker stops mid-task or abandons the operation.
    interrupted: str
    # The failure recorded when the step raises an unexpected error.
    unexpected: str
    # How long an operation of this kind may stay queued or running before recovery treats
    # it as abandoned by its worker, or ``None`` when recovery never touches it.
    stale_after: timedelta | None
    # Why a dispatched operation that was interrupted or abandoned is reconciling; ``None``
    # for kinds that never dispatch.
    uncertain: str | None = None
    # Establishes a reconciling operation's outcome from native evidence, given the
    # operation and the revision its check started.
    reconcile: Callable[[int, int], None] | None = None


_POLICIES: dict[str, _Policy] = {}


def register[M: RemoteOperation](
    model: type[M],
    step: Callable[[M], None],
    *,
    interrupted: str,
    unexpected: str,
    stale_after: timedelta | None,
    uncertain: str | None = None,
    reconcile: Callable[[M], None] | None = None,
) -> None:
    """Register ``model`` as a kind's details and ``step`` as its work.

    ``step`` receives the claimed operation as ``model``, with its server loaded. It
    publishes a success itself through ``succeed`` or ``finish``; raising records a
    failure, or reconciliation once the operation was dispatched. A kind that dispatches
    gives ``uncertain`` and ``reconcile``, which receives a reconciling operation whose
    ``revision`` is the one its check started with; it records through ``note``,
    ``finish`` and its own conditional updates with that revision.
    """

    def load(operation_id: int) -> M:
        return model.objects.select_related("server").get(pk=operation_id)

    def load_and_step(operation_id: int) -> None:
        step(load(operation_id))

    reconciler = None
    if reconcile is not None:
        inspect = reconcile

        def reconciler(operation_id: int, revision: int) -> None:
            operation = load(operation_id)
            # A newer check may have started since; this one keeps its own revision, so
            # none of its records can land after the newer check's.
            operation.revision = revision
            inspect(operation)

    _POLICIES[model.KIND] = _Policy(
        load_and_step, interrupted, unexpected, stale_after, uncertain, reconciler
    )


def _advance(
    operations: QuerySet[RemoteOperation],
    source: RemoteOperation.Status,
    target: RemoteOperation.Status,
    **changes: object,
) -> int:
    return operations.filter(status=source).update(status=target, **changes)


def _tasks(operation_ids: Iterable[int] | None = None) -> DBTaskResultQuerySet:
    """Only this function knows how the database task backend stores an operation's task.

    Tests read and age task records through ``discovery.fakes``, which calls it.
    """
    tasks = DBTaskResult.objects.filter(task_path=run_remote_operation.module_path)
    if operation_ids is None:
        return tasks
    return tasks.filter(args_kwargs__args__0__in=list(operation_ids))


def _recover_stale_operations() -> int:
    now = timezone.now()
    recovered = 0
    for kind, policy in _POLICIES.items():
        if policy.stale_after is None:
            continue
        cutoff = now - policy.stale_after
        interrupted = {"finished_at": now, "failure": policy.interrupted}
        of_kind = RemoteOperation.objects.filter(kind=kind)
        abandoned = of_kind.filter(started_at__lt=cutoff)
        if policy.uncertain is not None:
            recovered += _advance(
                abandoned.filter(dispatched_at__isnull=False),
                Status.RUNNING,
                Status.RECONCILING,
                failure=policy.uncertain,
            )
        recovered += _advance(
            abandoned.filter(dispatched_at__isnull=True),
            Status.RUNNING,
            Status.FAILED,
            **interrupted,
        )
        stale_queued = of_kind.filter(status=Status.QUEUED, queued_at__lt=cutoff)
        for pk in stale_queued.values_list("pk", flat=True):
            tasks = _tasks([pk])
            waiting = tasks.filter(status=TaskResultStatus.READY).exists()
            claiming = tasks.filter(
                status=TaskResultStatus.RUNNING, started_at__gte=cutoff
            ).exists()
            if not waiting and not claiming:
                recovered += _advance(
                    RemoteOperation.objects.filter(pk=pk),
                    Status.QUEUED,
                    Status.FAILED,
                    **interrupted,
                )
    if recovered:
        logger.info("Recovered %s interrupted remote operations", recovered)
    return recovered


def recovers_first[**P, R](entry: Callable[P, R]) -> Callable[P, R]:
    """Make ``entry`` recover abandoned operations before doing anything else.

    Kind services decorate every public function with it, directly or through another,
    so none reads, queues or runs operations while an abandoned one still looks active.
    """

    @functools.wraps(entry)
    def recovering(*args: P.args, **kwargs: P.kwargs) -> R:
        _recover_stale_operations()
        return entry(*args, **kwargs)

    return recovering


def queue[M: RemoteOperation](model: type[M], server: Server, **details: object) -> M:
    """Queue an operation of ``model``'s kind; raise ``OperationBusy`` if one is active.

    The database task backend stores the task in this database, so the operation and its
    task are committed together or not at all. Call it from a function that recovers first.
    """
    if model.KIND not in _POLICIES:
        raise ImproperlyConfigured(f"No step is registered for {model.KIND} operations.")
    try:
        with transaction.atomic():
            operation = model.objects.create(server=server, ssh_alias=server.ssh_alias, **details)
            run_remote_operation.enqueue(operation.pk)
    except IntegrityError:
        active = active_operation(server)
        if active is not None:
            raise OperationBusy(active) from None
        if not Server.objects.filter(pk=server.pk).exists():
            # Removed by a concurrent request; neither the operation nor its task was saved.
            raise Server.DoesNotExist from None
        raise
    return operation


def active_operation(server: Server) -> RemoteOperation | None:
    """Call it from a function that recovers first."""
    return RemoteOperation.objects.filter(server=server, status__in=RemoteOperation.ACTIVE).first()


def forget(operations: QuerySet[RemoteOperation]) -> None:
    """Delete those of ``operations`` that finished, with the worker's task records.

    Call it inside the transaction that deletes their server, from a function that
    recovers first.
    """
    finished = operations.exclude(status__in=RemoteOperation.ACTIVE)
    _forget_tasks(finished)
    finished.delete()


def detach(operations: QuerySet[RemoteOperation]) -> None:
    """Keep those of ``operations`` that finished as audit without their server.

    Call it inside the transaction that deletes their server, from a function that
    recovers first.
    """
    finished = operations.exclude(status__in=RemoteOperation.ACTIVE)
    _forget_tasks(finished)
    finished.update(server=None)


def _forget_tasks(finished: QuerySet[RemoteOperation]) -> None:
    # Every task record naming a finished operation goes, whatever became of the task,
    # except one a worker claimed recently: that worker saves the record when it finishes.
    # A claim older than every stale limit belongs to a stopped worker.
    limits = [policy.stale_after for policy in _POLICIES.values() if policy.stale_after]
    recent = timezone.now() - max(limits, default=timedelta())
    _tasks(finished.values_list("pk", flat=True)).exclude(
        status=TaskResultStatus.RUNNING, started_at__gte=recent
    ).delete()


@recovers_first
def run(operation_id: int) -> None:
    """Called by the worker only. The operation it runs is recent, so recovery skips it."""
    claimed = _advance(
        RemoteOperation.objects.filter(pk=operation_id),
        Status.QUEUED,
        Status.RUNNING,
        started_at=timezone.now(),
    )
    found = RemoteOperation.objects.filter(pk=operation_id).values_list("kind", "status").first()
    if found is None:
        # Removed with its server.
        return
    kind, status = found
    if claimed:
        _run(operation_id, _POLICIES[kind])
    elif status == Status.RECONCILING:
        _reconcile(operation_id, _POLICIES[kind])
    # Otherwise recovered as interrupted, or already handled.


def check(operation: RemoteOperation) -> bool:
    policy = _POLICIES.get(operation.kind)
    if policy is None or policy.reconcile is None:
        return False
    with transaction.atomic():
        asked = RemoteOperation.objects.filter(pk=operation.pk, status=Status.RECONCILING).update(
            check_requested_at=timezone.now()
        )
        if asked:
            run_remote_operation.enqueue(operation.pk)
    return bool(asked)


def _begin_check(operation_id: int) -> tuple[int, datetime] | None:
    started = timezone.now()
    with transaction.atomic():
        begun = RemoteOperation.objects.filter(pk=operation_id, status=Status.RECONCILING).update(
            revision=F("revision") + 1
        )
        if not begun:
            return None
        revision = RemoteOperation.objects.values_list("revision", flat=True).get(pk=operation_id)
    return revision, started


def _reconcile(operation_id: int, policy: _Policy) -> None:
    if policy.reconcile is None:
        return
    begun = _begin_check(operation_id)
    if begun is None:
        return
    revision, started = begun
    try:
        policy.reconcile(operation_id, revision)
    except (ConnectionFailed, OperationRefused) as failure:
        note(operation_id, f"{failure} {policy.uncertain or ''}".strip(), revision=revision)
    except Exception as error:
        # Log the type only: a message or traceback could quote remote data.
        logger.error(
            "Checking remote operation %s failed unexpectedly: %s",
            operation_id,
            type(error).__name__,
        )
        note(
            operation_id,
            f"{policy.unexpected} {policy.uncertain or ''}".strip(),
            revision=revision,
        )
    finally:
        # A request made after this check started still waits for its own check.
        RemoteOperation.objects.filter(pk=operation_id, check_requested_at__lte=started).update(
            check_requested_at=None
        )


def _run(operation_id: int, policy: _Policy) -> None:
    try:
        policy.step(operation_id)
    except (ConnectionFailed, OperationRefused) as failure:
        _finish_failed(operation_id, policy, str(failure))
    except Exception as error:
        # Log the type only: a message or traceback could quote remote data.
        logger.error(
            "Remote operation %s failed unexpectedly: %s", operation_id, type(error).__name__
        )
        _finish_failed(operation_id, policy, policy.unexpected)
    except BaseException:
        # Forcing the worker to stop exits mid-task; record the interruption now rather
        # than leaving the server busy until recovery.
        _finish_failed(operation_id, policy, policy.interrupted)
        raise


def succeed(operation_id: int, finished_at: datetime, **changes: object) -> bool:
    """Mark a running operation succeeded; return whether it still was running.

    Call it inside the transaction that publishes the step's result, and publish only
    when it returns ``True``: a recovery that already marked the operation interrupted
    wins, so a stale worker never publishes after recovery.
    """
    return bool(
        _advance(
            RemoteOperation.objects.filter(pk=operation_id),
            Status.RUNNING,
            Status.SUCCEEDED,
            finished_at=finished_at,
            **changes,
        )
    )


def dispatch(operation_id: int, **changes: object) -> bool:
    """Record that the running operation is about to send a change; return whether it may.

    Call it before sending anything that may change the server, and send only when it
    returns ``True``: a recovery that already failed the operation wins, so a stale worker
    never dispatches. From then on the operation closes only from native evidence.
    """
    return bool(
        _advance(
            RemoteOperation.objects.filter(pk=operation_id, dispatched_at__isnull=True),
            Status.RUNNING,
            Status.RUNNING,
            dispatched_at=timezone.now(),
            **changes,
        )
    )


def reconcile(operation_id: int, reason: str) -> bool:
    return bool(
        _advance(
            RemoteOperation.objects.filter(pk=operation_id),
            Status.RUNNING,
            Status.RECONCILING,
            failure=reason,
        )
    )


def _at(operation_id: int, revision: int | None) -> QuerySet[RemoteOperation]:
    operations = RemoteOperation.objects.filter(pk=operation_id)
    return operations if revision is None else operations.filter(revision=revision)


def note(operation_id: int, reason: str, *, revision: int | None = None) -> bool:
    """Replace a reconciling operation's explanation; return whether it was replaced.

    A check passes its ``revision``: the explanation is kept only while no newer check
    has started.
    """
    return bool(
        _advance(
            _at(operation_id, revision), Status.RECONCILING, Status.RECONCILING, failure=reason
        )
    )


def finish(
    operation_id: int,
    source: RemoteOperation.Status,
    *,
    succeeded: bool,
    failure: str = "",
    revision: int | None = None,
) -> bool:
    """Close an operation still in ``source``, running or reconciling; return whether it was.

    For kinds that establish their outcome themselves. Call it inside the transaction that
    records the outcome's details, and record them only when it returns ``True``, as with
    ``succeed``. A check passes its ``revision``, so it closes the operation only while no
    newer check has started.
    """
    return bool(
        _advance(
            _at(operation_id, revision),
            source,
            Status.SUCCEEDED if succeeded else Status.FAILED,
            finished_at=timezone.now(),
            failure=failure,
        )
    )


def _finish_failed(operation_id: int, policy: _Policy, failure: str) -> None:
    operations = RemoteOperation.objects.filter(pk=operation_id)
    # A stopped worker's own wording describes an undispatched operation.
    reason = policy.uncertain if failure == policy.interrupted else f"{failure} {policy.uncertain}"
    if policy.uncertain is not None and _advance(
        operations.filter(dispatched_at__isnull=False),
        Status.RUNNING,
        Status.RECONCILING,
        failure=reason,
    ):
        logger.info("Remote operation %s is reconciling", operation_id)
        return
    _advance(
        operations,
        Status.RUNNING,
        Status.FAILED,
        finished_at=timezone.now(),
        failure=failure,
    )
    # The sanitized reason is recorded on the operation and shown in the dashboard.
    logger.info("Remote operation %s failed", operation_id)
