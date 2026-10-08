"""docs/wordpress.md#wp-cli-setup"""

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction

from bootstrap.models import Action, PlanPreparation
from bootstrap.services import ServerPlans, read_plans
from operations import lifecycle
from operations.lifecycle import OperationBusy, recovers_first
from servers.models import Server

WORDPRESS_ACTIONS = (Action.WPCLI,)


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
