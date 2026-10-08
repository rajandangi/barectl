"""docs/wordpress.md#wp-cli-setup"""

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction

from bootstrap.apply import index_changes
from bootstrap.models import Action, ApplyRun, PlanPreparation
from bootstrap.plans import with_plans
from bootstrap.presentation import apply_view, view
from bootstrap.services import ServerPlans, in_family, read_plans, request_preparation
from operations import lifecycle
from operations.lifecycle import OperationBusy, recovers_first
from servers.models import Server

from .models import WordpressRequest

WORDPRESS_ACTIONS = (Action.WPCLI,)
RUNTIME_ACTIONS = (Action.PHP_WORDPRESS,)


@recovers_first
@transaction.atomic
def request_setup_preparation(server: Server, user: AbstractBaseUser) -> PlanPreparation | None:
    """Queue a WP-CLI setup plan's preparation, or ``None`` if an operation is active."""
    try:
        preparation = lifecycle.queue(
            PlanPreparation, server, action=Action.WPCLI, requested_by=user
        )
    except OperationBusy:
        return None
    return preparation


@recovers_first
def read_wordpress_plans(server: Server) -> ServerPlans:
    return read_plans(server, WORDPRESS_ACTIONS)


@recovers_first
def request_runtime_preparation(
    server: Server, user: AbstractBaseUser, identifier: str
) -> PlanPreparation | None:
    """Queue a WordPress PHP runtime plan's preparation for one site with its request, or
    ``None`` if an operation is active. Raises ``Server.DoesNotExist`` when a concurrent
    request removed the server."""
    with transaction.atomic():
        preparation = request_preparation(server, user, Action.PHP_WORDPRESS)
        if preparation is not None:
            WordpressRequest.objects.create(preparation=preparation, identifier=identifier)
        return preparation


@recovers_first
def read_site_runtime(server: Server, identifier: str) -> ServerPlans:
    """The server's runtime plans for one site, newest first."""
    family: list[str] = [*RUNTIME_ACTIONS]
    preparations = with_plans(
        PlanPreparation.objects.filter(
            server=server, action__in=family, wordpress_request__identifier=identifier
        )
    )
    active = lifecycle.active_operation(server)
    refreshes = index_changes(server.pk)
    latest_apply = ApplyRun.objects.filter(
        server=server,
        action__in=family,
        plan__preparation__wordpress_request__identifier=identifier,
    ).first()
    return ServerPlans(
        [view(preparation, refreshes) for preparation in preparations],
        other_active=active is not None and not in_family(active, family),
        latest_apply=None if latest_apply is None else apply_view(latest_apply),
    )
