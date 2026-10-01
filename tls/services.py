"""docs/tls.md#preparing-a-challenge-route"""

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction

from bootstrap.models import Action, PlanPreparation
from bootstrap.services import ServerPlans, read_plans
from operations import lifecycle
from operations.lifecycle import OperationBusy, recovers_first
from servers.models import Server

from .models import TlsRequest

TLS_ACTIONS = (Action.CERTBOT, Action.TLS_CHALLENGE)


@recovers_first
def request_challenge_preparation(
    server: Server, user: AbstractBaseUser, identifier: str
) -> PlanPreparation | None:
    """Queue a challenge route plan's preparation, or ``None`` if an operation is active.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    with transaction.atomic():
        try:
            preparation = lifecycle.queue(
                PlanPreparation, server, action=Action.TLS_CHALLENGE, requested_by=user
            )
        except OperationBusy:
            return None
        TlsRequest.objects.create(preparation=preparation, identifier=identifier)
    return preparation


@recovers_first
def request_setup_preparation(server: Server, user: AbstractBaseUser) -> PlanPreparation | None:
    """Queue a renewal setup plan's preparation, or ``None`` if an operation is active."""
    with transaction.atomic():
        try:
            preparation = lifecycle.queue(
                PlanPreparation, server, action=Action.CERTBOT, requested_by=user
            )
        except OperationBusy:
            return None
        TlsRequest.objects.create(preparation=preparation, identifier="")
    return preparation


def read_tls_plans(server: Server) -> ServerPlans:
    return read_plans(server, TLS_ACTIONS)
