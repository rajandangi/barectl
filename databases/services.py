"""docs/databases.md#preparing-a-database-plan"""

from django.contrib.auth.models import AbstractBaseUser

from bootstrap.models import Action, PlanPreparation
from bootstrap.profiles import DRIVER_ACTIONS
from bootstrap.services import ServerPlans, read_plans, request_preparation
from operations.lifecycle import recovers_first
from servers.models import Server

DATABASE_ACTIONS = tuple(sorted(DRIVER_ACTIONS))


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
