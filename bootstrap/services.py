"""docs/adr/0004-serialize-remote-operations-in-one-table.md"""

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from discovery import ssh
from operations import lifecycle
from operations.lifecycle import OperationBusy, OperationRefused, recovers_first
from operations.models import RemoteOperation
from servers.models import Server

from . import actions
from .apply import current_units, index_changes
from .inspection import inspect
from .models import Action, ApplyRun, PlanPreparation
from .plans import save_plan, with_plans
from .presentation import ApplyView, PreparationView, apply_view, view
from .review import review

logger = logging.getLogger(__name__)

UNEXPECTED_FAILURE = (
    "Plan preparation stopped because of an unexpected error. Barectl did not record the "
    "error details, which could include remote output. The worker log names the error type."
)
INTERRUPTED_FAILURE = (
    "The worker stopped before finishing this plan preparation. Preparation only reads the "
    "server, so nothing changed there. Prepare the plan again."
)
REVOKED_FAILURE = (
    "The account that requested this plan is no longer active or no longer allowed to "
    "prepare plans, so Barectl did not connect to the server."
)
# Preparation is bounded by the connection's limits (ssh.SESSION_TIMEOUT), so one older
# than this was abandoned.
STALE_AFTER = timedelta(minutes=10)


@dataclass(frozen=True)
class ServerPlans:
    # Every recorded preparation, newest first, each with its plan once prepared.
    history: list[PreparationView]
    # Another remote operation than this section's plans and runs is active, such as a
    # connection check.
    other_active: bool
    latest_apply: ApplyView | None = None

    @property
    def latest(self) -> PreparationView | None:
        return self.history[0] if self.history else None

    @property
    def polling(self) -> bool:
        return (
            self.other_active
            or (self.latest is not None and self.latest.active)
            or (self.latest_apply is not None and self.latest_apply.active)
        )

    @property
    def can_prepare(self) -> bool:
        """Whether a preparation may be requested now, permissions aside."""
        return not self.polling


@recovers_first
def request_preparation(
    server: Server, user: AbstractBaseUser, action: Action
) -> PlanPreparation | None:
    """Queue a preparation of ``action``, or return ``None`` if an operation is active.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    try:
        return lifecycle.queue(PlanPreparation, server, action=action, requested_by=user)
    except OperationBusy:
        return None


@recovers_first
def read_plans(server: Server, family: Iterable[str] = actions.BUILT_IN) -> ServerPlans:
    """The server's plans and runs of the actions in ``family``, which one section shows."""
    shown = list(family)
    preparations = with_plans(PlanPreparation.objects.filter(server=server, action__in=shown))
    active = lifecycle.active_operation(server)
    refreshes = index_changes(server.pk)
    latest_apply = ApplyRun.objects.filter(server=server, action__in=shown).first()
    return ServerPlans(
        [view(preparation, refreshes) for preparation in preparations],
        other_active=active is not None and not in_family(active, shown),
        latest_apply=None if latest_apply is None else apply_view(latest_apply),
    )


def in_family(operation: RemoteOperation, family: list[str]) -> bool:
    """Whether an active operation belongs to ``family``, so it is not another section's."""
    if operation.kind == RemoteOperation.Kind.PLAN_PREPARATION:
        model: type[PlanPreparation | ApplyRun] = PlanPreparation
    elif operation.kind == RemoteOperation.Kind.APPLY:
        model = ApplyRun
    else:
        return False
    return model.objects.filter(pk=operation.pk, action__in=family).exists()


@recovers_first
def read_preparation(operation_id: int) -> PreparationView | None:
    found = with_plans(PlanPreparation.objects.filter(pk=operation_id)).first()
    if found is None or found.server_id is None:
        return None
    return view(found, index_changes(found.server_id))


@recovers_first
def preparation_history(
    shown: Iterable[str], server: Server | None = None, matching: Q | None = None
) -> list[PreparationView]:
    """Every preparation of the ``shown`` actions for Activity, of ``server`` when given and
    ``matching`` the condition when given."""
    preparations = PlanPreparation.objects.filter(action__in=list(shown))
    if server is not None:
        preparations = preparations.filter(server=server)
    if matching is not None:
        preparations = preparations.filter(matching)
    return [view(preparation) for preparation in with_plans(preparations)]


@recovers_first
def recorded_plans(server: Server, shown: Iterable[str]) -> int:
    """How many preparations of the ``shown`` actions removing the server would delete."""
    return PlanPreparation.objects.filter(server=server, action__in=list(shown)).count()


@recovers_first
def forget_plans(server: Server) -> None:
    """Call inside the transaction that deletes the server. Active preparations are kept and
    protect the server, so the database refuses the removal while one remains.
    """
    lifecycle.forget(
        RemoteOperation.objects.filter(server=server, kind=RemoteOperation.Kind.PLAN_PREPARATION)
    )


def _prepare(preparation: PlanPreparation) -> None:
    requester = preparation.requested_by
    required = actions.authority(preparation.action).prepare
    if requester is None or not requester.is_active or not requester.has_perms(required):
        raise OperationRefused(REVOKED_FAILURE)
    action = Action(preparation.action)
    handler = actions.extension(action)
    collected_at = timezone.now()
    with ssh.connect_alias(preparation.ssh_alias) as shell:
        if handler is not None:
            draft = handler.prepare(preparation, shell)
        else:
            evidence = inspect(shell, action)
        host_key = shell.host_key
    if handler is None:
        draft = review(action, evidence, current_units())
    # Publish the plan and the outcome together; a recovery that already marked this
    # preparation interrupted wins, so a stale worker never records a plan after it.
    with transaction.atomic():
        if not lifecycle.succeed(preparation.pk, timezone.now(), host_key=host_key):
            return
        plan = save_plan(preparation, draft, host_key=host_key, collected_at=collected_at)
        if handler is not None:
            handler.save(plan, draft)
    logger.info("Plan preparation %s succeeded", preparation.pk)


lifecycle.register(
    PlanPreparation,
    _prepare,
    interrupted=INTERRUPTED_FAILURE,
    unexpected=UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
)
