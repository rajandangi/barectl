"""One authorized control composes fresh review and the existing native runtime steps."""

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.tasks import task
from django.utils import timezone

from operations import lifecycle
from operations.models import RemoteOperation
from servers.models import Server

from .actions import BOOTSTRAP
from .apply import request_apply
from .models import Action, ConfigurationPlan, Verification
from .runtime_models import RuntimeChange, RuntimeChangeStep, RuntimePlan
from .runtime_services import request_runtime_preparation
from .services import request_preparation
from .source_tools_models import SourceToolsSelection

PERMISSIONS = tuple(dict.fromkeys((*BOOTSTRAP.prepare, *BOOTSTRAP.apply)))


def request_php_default(server: Server, user: User, branch: str) -> RuntimeChange | None:
    return _request(server, user, branch, "")


def request_site_php_switch(
    server: Server, user: User, identifier: str, branch: str
) -> RuntimeChange | None:
    from sites.names import IDENTIFIER

    if not IDENTIFIER.fullmatch(identifier):
        return None
    return _request(server, user, branch, identifier)


def _permissions(identifier: str) -> tuple[str, ...]:
    if not identifier:
        return PERMISSIONS
    from sites.runtime_handler import HANDLER

    authority = HANDLER.authority

    return tuple(dict.fromkeys((*PERMISSIONS, *authority.prepare, *authority.apply)))


@lifecycle.recovers_first
def _request(server: Server, user: User, branch: str, identifier: str) -> RuntimeChange | None:
    if (
        branch not in ("8.3", "8.4", "8.5")
        or not user.is_active
        or not user.has_perms(_permissions(identifier))
    ):
        return None
    try:
        with transaction.atomic():
            current = RuntimeChange.objects.filter(
                server=server, status=RuntimeChange.Status.ACTIVE
            ).first()
            if current is not None:
                return (
                    current
                    if (current.requested_by_id, current.branch, current.identifier)
                    == (user.pk, branch, identifier)
                    else None
                )
            if lifecycle.active_operation(server) is not None:
                return None
            change = RuntimeChange.objects.create(
                server=server,
                requested_by=user,
                branch=branch,
                identifier=identifier,
                action=Action.SITE_PHP_SWITCH if identifier else Action.PHP_DEFAULT,
                ssh_alias=server.ssh_alias,
            )
            advance_runtime_change.enqueue(change.pk)
            return change
    except IntegrityError:
        return None


def completed(operation_ids: list[int]) -> None:
    changes = set(
        RuntimeChangeStep.objects.filter(
            Q(preparation_id__in=operation_ids) | Q(run_id__in=operation_ids),
            change__status=RuntimeChange.Status.ACTIVE,
        ).values_list("change_id", flat=True)
    )
    servers = RemoteOperation.objects.filter(
        pk__in=operation_ids, kind=RemoteOperation.Kind.DISCOVERY
    ).values_list("server_id", flat=True)
    changes.update(
        RuntimeChange.objects.filter(
            server_id__in=servers, status=RuntimeChange.Status.ACTIVE
        ).values_list("pk", flat=True)
    )
    for change_id in changes:
        advance_runtime_change.enqueue(change_id)


@task(queue_name="default")
def advance_runtime_change(change_id: int) -> None:
    with transaction.atomic():
        change = (
            RuntimeChange.objects.select_for_update()
            .select_related("server", "requested_by")
            .get(pk=change_id)
        )
        if change.status != RuntimeChange.Status.ACTIVE:
            return
        server, user = change.server, change.requested_by
        if (
            server is None
            or user is None
            or not user.is_active
            or not user.has_perms(_permissions(change.identifier))
            or server.ssh_alias != change.ssh_alias
        ):
            _stop(
                change,
                "The connection or runtime authorization changed. No later step was started.",
            )
            return
        last = change.steps.select_related("preparation", "run").order_by("-position").first()
        if last is not None and not _complete(change, last):
            return
        if lifecycle.active_operation(server) is not None:
            return
        action = _next_action(change, last)
        if action is None:
            return
        preparation = (
            request_runtime_preparation(server, user, change.branch, identifier=change.identifier)
            if action in (Action.PHP_DEFAULT, Action.SITE_PHP_SWITCH)
            else request_preparation(server, user, action)
        )
        if preparation is None:
            _stop(change, "Another operation is active. No later runtime step was started.")
            return
        RuntimeChangeStep.objects.create(
            change=change,
            position=0 if last is None else last.position + 1,
            preparation=preparation,
        )


def _complete(change: RuntimeChange, step: RuntimeChangeStep) -> bool:
    operation: RemoteOperation | None = step.run or step.preparation
    if operation is None:
        _stop(
            change,
            "The runtime step record is missing. Inspect native state before another request.",
        )
        return False
    if operation.status in RemoteOperation.ACTIVE:
        return False
    if operation.status != RemoteOperation.Status.SUCCEEDED or (
        step.run is not None and step.run.verification != Verification.PASSED
    ):
        _stop(change, operation.failure or "The runtime step did not verify successfully.")
        return False
    if step.run is not None:
        return True
    return _apply_prepared(change, step)


def _apply_prepared(change: RuntimeChange, step: RuntimeChangeStep) -> bool:
    plan = ConfigurationPlan.objects.filter(preparation=step.preparation).first()
    if plan is None or not plan.eligible:
        reasons = [] if plan is None else list(plan.refusals.values_list("text", flat=True))
        _stop(change, " ".join(reasons) or "The runtime review is unavailable.")
        return False
    if change.host_key and change.host_key != plan.host_key:
        _stop(change, "The server identity changed between runtime steps.")
        return False
    if not change.host_key:
        change.host_key = plan.host_key
        change.save(update_fields=["host_key"])
    if plan.no_changes:
        return True
    if (
        change.server is None
        or change.requested_by is None
        or lifecycle.active_operation(change.server) is not None
    ):
        return False
    applied = request_apply(plan, change.requested_by)
    if applied.run is None:
        _stop(change, applied.problem)
        return False
    step.run = applied.run
    step.save(update_fields=["run"])
    return False


def _next_action(change: RuntimeChange, last: RuntimeChangeStep | None) -> Action | None:
    if last is None:
        return Action.METADATA_REFRESH
    preparation = last.preparation
    if preparation is None:
        _stop(change, "The runtime preparation was removed.")
        return None
    plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
    if preparation.action == Action.PHP_SOURCE_PREREQUISITES:
        selection = SourceToolsSelection.objects.filter(plan=plan).first()
        if selection is None:
            _stop(change, "The fresh native PHP selection is missing.")
            return None
        if not selection.installed and selection.supply == "sury":
            return Action.PHP_SOURCE
        return Action(change.action)
    if preparation.action == Action.PHP_SOURCE:
        return Action.METADATA_REFRESH
    if preparation.action == Action.METADATA_REFRESH:
        return Action.PHP_SOURCE_PREREQUISITES if last.position == 0 else Action(change.action)
    runtime = RuntimePlan.objects.filter(plan=plan).first()
    if runtime is None:
        _stop(change, "The runtime review was removed.")
        return None
    if runtime.package_action:
        return Action(change.action)
    change.status = RuntimeChange.Status.SUCCEEDED
    change.finished_at = timezone.now()
    change.save(update_fields=["status", "finished_at"])
    return None


def _stop(change: RuntimeChange, failure: str) -> None:
    change.status = RuntimeChange.Status.FAILED
    change.failure = failure
    change.finished_at = timezone.now()
    change.save(update_fields=["status", "failure", "finished_at"])


lifecycle.register_completion(completed)
