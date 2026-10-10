"""One authorized native Node selection (docs/node-runtimes-native-design.md)."""

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.tasks import task
from django.utils import timezone

from bootstrap import actions
from bootstrap.apply import request_apply
from bootstrap.models import Action, ConfigurationPlan, Verification
from bootstrap.services import request_preparation
from discovery.services import queue_discovery
from operations import lifecycle
from operations.models import RemoteOperation
from servers.models import Server
from sites.names import valid_identifier

from . import catalog
from . import permissions as authority
from .models import RuntimeChange, RuntimeChangeStep
from .services import request_runtime_preparation

STAGES = (Action.METADATA_REFRESH, Action.PHP_SOURCE_PREREQUISITES, Action.NODE_RUNTIME)


def permissions(identifier: str = "") -> tuple[str, ...]:
    required = {
        p
        for stage in STAGES
        for p in (*actions.authority(stage).prepare, *actions.authority(stage).apply)
    }
    required.update(
        (*authority.required(identifier, "prepare"), *authority.required(identifier, "apply"))
    )
    return tuple(sorted(required))


@lifecycle.recovers_first
def request_runtime_change(
    server: Server, user_id: int, version: str, *, identifier: str = ""
) -> RuntimeChange | None:
    if version not in catalog.VERSIONS or (identifier and not valid_identifier(identifier)):
        raise ValueError("Select a reviewed exact Node LTS release and valid site.")
    user = User.objects.filter(pk=user_id, is_active=True).first()
    if user is None or not user.has_perms(permissions(identifier)):
        return None
    try:
        with transaction.atomic():
            Server.objects.select_for_update().get(pk=server.pk)
            if lifecycle.active_operation(server) is not None:
                return None
            active = RuntimeChange.objects.filter(server=server, status="active").first()
            if active is not None:
                return (
                    active
                    if active.requested_by_id == user_id
                    and active.version == version
                    and active.identifier == identifier
                    else None
                )
            change = RuntimeChange.objects.create(
                server=server,
                requested_by=user,
                version=version,
                identifier=identifier,
                ssh_alias=server.ssh_alias,
            )
            advance.enqueue(change.pk)
            return change
    except IntegrityError:
        return None


def completed(operation_ids: list[int]) -> None:
    ids = (
        RuntimeChangeStep.objects.filter(
            Q(preparation_id__in=operation_ids) | Q(run_id__in=operation_ids),
            change__status="active",
        )
        .values_list("change_id", flat=True)
        .distinct()
    )
    discovered_servers = RemoteOperation.objects.filter(
        pk__in=operation_ids, kind=RemoteOperation.Kind.DISCOVERY
    ).values_list("server_id", flat=True)
    refreshed = RuntimeChange.objects.filter(
        server_id__in=discovered_servers, status="active"
    ).values_list("pk", flat=True)
    for change_id in set(ids) | set(refreshed):
        advance.enqueue(change_id)


def _stop(change: RuntimeChange, failure: str) -> None:
    change.status, change.failure, change.finished_at = "failed", failure, timezone.now()
    change.save(update_fields=["status", "failure", "finished_at"])


def _finish_step(change: RuntimeChange, step: RuntimeChangeStep) -> bool:
    operation = step.run or step.preparation
    if operation is None:
        _stop(change, "The stage record is missing. Inspect native state.")
        return False
    if operation.status in RemoteOperation.ACTIVE:
        return False
    if operation.status != RemoteOperation.Status.SUCCEEDED:
        _stop(change, operation.failure or "The Node stage stopped.")
        return False
    if not change.host_key:
        change.host_key = operation.host_key
        change.save(update_fields=["host_key"])
    if not operation.host_key or operation.host_key != change.host_key:
        _stop(change, "The server identity changed; no later stage started.")
        return False
    if step.run is not None:
        if step.run.verification != Verification.PASSED:
            _stop(change, "The Node stage did not verify successfully.")
            return False
        return True
    return _apply_prepared(change, step)


def _apply_prepared(change: RuntimeChange, step: RuntimeChangeStep) -> bool:
    plan = ConfigurationPlan.objects.filter(preparation=step.preparation).first()
    if plan is None or not plan.eligible or plan.host_key != change.host_key:
        reasons = [] if plan is None else list(plan.refusals.values_list("text", flat=True))
        _stop(change, " ".join(reasons) or "The stage has no eligible review.")
        return False
    if plan.no_changes:
        return True
    user = change.requested_by
    if user is None:
        return False
    if change.server is None:
        _stop(change, "The server registration was removed; no later stage started.")
        return False
    active = lifecycle.active_operation(change.server)
    if active is not None and active.kind == RemoteOperation.Kind.DISCOVERY:
        return False
    result = request_apply(plan, user)
    if result.run is None:
        _stop(change, result.problem)
        return False
    step.run = result.run
    step.save(update_fields=["run"])
    return False


def _current_request(change: RuntimeChange) -> tuple[Server, User] | None:
    if change.server is None:
        _stop(change, "The server registration was removed; no later stage started.")
        return None
    if change.version not in catalog.VERSIONS or (
        change.identifier and not valid_identifier(change.identifier)
    ):
        _stop(change, "The runtime request is no longer a supported exact selection.")
        return None
    user = change.requested_by
    if user is None or not user.is_active or not user.has_perms(permissions(change.identifier)):
        _stop(change, "The requesting account can no longer change Node runtimes.")
        return None
    if change.server.ssh_alias != change.ssh_alias:
        _stop(change, "The server connection changed; no later stage started.")
        return None
    return change.server, user


@task
def advance(change_id: int) -> None:
    with transaction.atomic():
        change = (
            RuntimeChange.objects.select_for_update()
            .select_related("server", "requested_by")
            .filter(pk=change_id, status="active")
            .first()
        )
        if change is None:
            return
        current = _current_request(change)
        if current is None:
            return
        server, user = current
        step = change.steps.select_related("preparation", "run").order_by("position").last()
        if step is not None and not _finish_step(change, step):
            return
        position = 0 if step is None else step.position + 1
        if position == len(STAGES):
            change.status, change.finished_at = "succeeded", timezone.now()
            change.save(update_fields=["status", "finished_at"])
            queue_discovery(server)
            return
        active = lifecycle.active_operation(server)
        if active is not None and active.kind == RemoteOperation.Kind.DISCOVERY:
            return
        if active is not None:
            _stop(change, "Another operation started; prepare a new Node change after it settles.")
            return
        preparation = (
            request_runtime_preparation(server, user, change.version, identifier=change.identifier)
            if STAGES[position] == Action.NODE_RUNTIME
            else request_preparation(server, user, STAGES[position])
        )
        if preparation is None:
            _stop(change, "Another operation is active.")
            return
        RuntimeChangeStep.objects.create(change=change, position=position, preparation=preparation)
