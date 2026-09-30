"""docs/databases.md#preparing-a-database-plan"""

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction

from bootstrap.models import Action, PlanPreparation
from bootstrap.profiles import DRIVER_ACTIONS
from bootstrap.services import ServerPlans, read_plans, request_preparation
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


@recovers_first
def request_driver_preparation(
    server: Server, user: AbstractBaseUser, action: Action
) -> PlanPreparation | None:
    """Queue a driver plan's preparation, or ``None`` if an operation is active.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    return request_preparation(server, user, action)


def read_database_plans(server: Server) -> ServerPlans:
    return read_plans(server, DATABASE_ACTIONS)


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
