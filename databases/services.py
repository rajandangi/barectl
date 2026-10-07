"""docs/databases.md#preparing-a-database-plan"""

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction

from bootstrap.apply import index_changes
from bootstrap.models import Action, ApplyRun, PlanPreparation
from bootstrap.plans import with_plans
from bootstrap.presentation import apply_view, view
from bootstrap.profiles import DRIVER_ACTIONS
from bootstrap.services import ServerPlans, in_family, read_plans, request_preparation
from discovery.models import DatabaseEngine
from operations import lifecycle
from operations.lifecycle import OperationBusy, recovers_first
from servers.models import Server

from . import binding
from .models import DatabaseRequest

DATABASE_ACTIONS = (
    *sorted(DRIVER_ACTIONS),
    *sorted(binding.BY_ACTION),
    Action.DATABASE_INSPECTION,
)
BINDING_ACTIONS = tuple(sorted(binding.BY_ACTION))


@recovers_first
def request_driver_preparation(
    server: Server,
    user: AbstractBaseUser,
    action: Action,
    *,
    php_version: str = "",
    php_supply: str = "ubuntu",
    identifier: str = "",
) -> PlanPreparation | None:
    """Queue a driver plan's preparation, or ``None`` if an operation is active.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    with transaction.atomic():
        preparation = request_preparation(server, user, action)
        if preparation is not None:
            DatabaseRequest.objects.create(
                preparation=preparation,
                php_version=php_version,
                php_supply=php_supply,
                identifier=identifier,
            )
        return preparation


def read_database_plans(server: Server) -> ServerPlans:
    return read_plans(server, DATABASE_ACTIONS)


@recovers_first
def read_site_bindings(server: Server, identifier: str) -> ServerPlans:
    """The server's binding plans for one site, newest first."""
    family = list(BINDING_ACTIONS)
    preparations = with_plans(
        PlanPreparation.objects.filter(
            server=server, action__in=family, database_request__identifier=identifier
        )
    )
    active = lifecycle.active_operation(server)
    refreshes = index_changes(server.pk)
    latest_apply = ApplyRun.objects.filter(
        server=server,
        action__in=family,
        plan__preparation__database_request__identifier=identifier,
    ).first()
    return ServerPlans(
        [view(preparation, refreshes) for preparation in preparations],
        other_active=active is not None and not in_family(active, family),
        latest_apply=None if latest_apply is None else apply_view(latest_apply),
    )


@recovers_first
def request_binding_preparation(
    server: Server, user: AbstractBaseUser, identifier: str, engine: DatabaseEngine
) -> PlanPreparation | None:
    """Queue a binding plan's preparation with its request, or ``None`` if an operation is
    active. Raises ``Server.DoesNotExist`` when a concurrent request removed the server."""
    action = binding.ENGINES[engine].action
    with transaction.atomic():
        try:
            preparation = lifecycle.queue(PlanPreparation, server, action=action, requested_by=user)
        except OperationBusy:
            return None
        DatabaseRequest.objects.create(
            preparation=preparation, identifier=identifier, engine=engine
        )
    return preparation


@recovers_first
def request_inspection(server: Server, user: AbstractBaseUser) -> PlanPreparation | None:
    return request_preparation(server, user, Action.DATABASE_INSPECTION)
