"""docs/sites.md#preparing-a-site-plan"""

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction

from bootstrap.models import Action, PlanPreparation
from bootstrap.services import ServerPlans, read_plans
from operations import lifecycle
from operations.lifecycle import OperationBusy, recovers_first
from servers.models import Server

from .models import SiteRequest

SITE_ACTIONS = (Action.SITE_HTTP,)


@recovers_first
def request_site_preparation(
    server: Server, user: AbstractBaseUser, identifier: str, names: tuple[str, ...]
) -> PlanPreparation | None:
    """Queue a site plan's preparation with its request, or ``None`` if an operation is active.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    with transaction.atomic():
        try:
            preparation = lifecycle.queue(
                PlanPreparation, server, action=Action.SITE_HTTP, requested_by=user
            )
        except OperationBusy:
            return None
        SiteRequest.objects.create(
            preparation=preparation, identifier=identifier, names="\n".join(names)
        )
    return preparation


def read_site_plans(server: Server) -> ServerPlans:
    return read_plans(server, SITE_ACTIONS)
