"""Explicit browser recovery.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

from datetime import timedelta

from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import Q
from django.tasks import task
from django.utils import timezone

from bootstrap.apply import request_apply
from bootstrap.models import Action, ApplyRun, ConfigurationPlan, PlanPreparation, Verification
from bootstrap.services import request_preparation
from operations import lifecycle
from operations.lifecycle import recovers_first
from operations.models import RemoteOperation
from servers.models import Server
from sites.names import valid_identifier

from . import first_access, inputs
from .access_reset_models import AccessResetIntent, AccessResetRequest

PERMISSIONS = (
    "servers.view_server",
    "wordpress.view_wordpressplan",
    "wordpress.prepare_wordpressplan",
    "discovery.view_siteobservation",
    "wordpress.manage_wordpress_credentials",
)


@recovers_first
def request_access_reset(
    server: Server, user_id: int, identifier: str, admin_login: str, first_access_spki: str
) -> PlanPreparation | None:
    user = User.objects.filter(pk=user_id, is_active=True).first()
    if user is None or not user.has_perms(PERMISSIONS):
        return None
    if not valid_identifier(identifier) or not inputs.LOGIN.fullmatch(admin_login):
        raise ValueError("Select a supported site and exact administrator login.")
    first_access.validate_key(first_access_spki)
    with transaction.atomic():
        Server.objects.select_for_update().get(pk=server.pk)
        existing = (
            AccessResetRequest.objects.select_related("preparation")
            .filter(
                preparation__server=server,
                preparation__requested_by=user,
                identifier=identifier,
                admin_login=admin_login,
                first_access_spki=first_access_spki,
            )
            .first()
        )
        if existing is not None:
            return existing.preparation
        preparation = request_preparation(server, user, Action.WORDPRESS_ACCESS)
        if preparation is not None:
            AccessResetRequest.objects.create(
                preparation=preparation,
                identifier=identifier,
                admin_login=admin_login,
                first_access_spki=first_access_spki,
                first_access_expires_at=timezone.now() + timedelta(hours=1),
            )
            AccessResetIntent.objects.create(preparation=preparation)
            advance.enqueue(preparation.pk)
        return preparation


def completed(operation_ids: list[int]) -> None:
    refreshed = RemoteOperation.objects.filter(
        pk__in=operation_ids, kind=RemoteOperation.Kind.DISCOVERY
    ).values_list("server_id", flat=True)
    ids = AccessResetIntent.objects.filter(
        Q(preparation_id__in=operation_ids)
        | Q(run_id__in=operation_ids)
        | Q(preparation__server_id__in=refreshed),
        status="active",
    ).values_list("preparation_id", flat=True)
    for preparation_id in ids:
        advance.enqueue(preparation_id)


def _stop(intent: AccessResetIntent, problem: str) -> None:
    intent.status, intent.failure = "failed", problem
    intent.save(update_fields=["status", "failure"])


def _apply(intent: AccessResetIntent, user: User) -> None:
    preparation = intent.preparation
    server = preparation.server
    if server is None or server.ssh_alias != preparation.ssh_alias:
        _stop(intent, "The server connection changed; no password reset was submitted.")
        return
    plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
    if (
        plan is None
        or not plan.eligible
        or not preparation.host_key
        or plan.host_key != preparation.host_key
    ):
        reasons = [] if plan is None else list(plan.refusals.values_list("text", flat=True))
        _stop(intent, " ".join(reasons) or "The reset has no eligible native review.")
        return
    if ApplyRun.objects.filter(plan=plan).exists():
        _stop(intent, "This request already has a native run; inspect its original outcome.")
        return
    active = lifecycle.active_operation(server)
    if active is not None and active.kind == RemoteOperation.Kind.DISCOVERY:
        return
    result = request_apply(plan, user)
    if result.run is None:
        _stop(intent, result.problem)
        return
    intent.run = result.run
    intent.save(update_fields=["run"])


@task
def advance(preparation_id: int) -> None:
    with transaction.atomic():
        intent = (
            AccessResetIntent.objects.select_for_update()
            .select_related("preparation__access_request", "preparation__requested_by", "run")
            .filter(preparation_id=preparation_id, status="active")
            .first()
        )
        if intent is None:
            return
        preparation = intent.preparation
        user_id = preparation.requested_by_id
        user = None if user_id is None else User.objects.filter(pk=user_id, is_active=True).first()
        if user is None or not user.has_perms(PERMISSIONS):
            _stop(intent, "The requesting account can no longer reset WordPress access.")
            return
        if intent.run is not None:
            run = intent.run
            if run.status in RemoteOperation.ACTIVE:
                return
            if (
                run.status != RemoteOperation.Status.SUCCEEDED
                or run.verification != Verification.PASSED
            ):
                _stop(intent, run.failure or "The original password-reset run did not verify.")
                return
            intent.status = "succeeded"
            intent.save(update_fields=["status"])
            return
        if preparation.status in RemoteOperation.ACTIVE:
            return
        if preparation.status != RemoteOperation.Status.SUCCEEDED:
            _stop(intent, preparation.failure or "The password-reset review stopped.")
            return
        if preparation.access_request.first_access_expires_at <= timezone.now():
            _stop(intent, "The browser key expired; no password reset was submitted.")
            return
        _apply(intent, user)
