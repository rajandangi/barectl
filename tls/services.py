"""docs/tls.md#preparing-a-challenge-route"""

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction

from bootstrap.apply import index_changes
from bootstrap.models import Action, PlanPreparation
from bootstrap.plans import with_plans
from bootstrap.presentation import view
from bootstrap.services import ServerPlans, in_family, read_plans
from operations import lifecycle
from operations.lifecycle import OperationBusy, recovers_first
from servers.models import Server

from .models import ActivationRequest, IssuanceRequest, StagingRequest, TlsRequest

TLS_ACTIONS = (
    Action.CERTBOT,
    Action.TLS_CHALLENGE,
    Action.TLS_READINESS,
    Action.TLS_STAGING,
    Action.TLS_ISSUANCE,
    Action.TLS_ACTIVATION,
)
READINESS_ACTIONS = (Action.TLS_READINESS.value,)


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
@transaction.atomic
def request_staging_preparation(
    server: Server, user: AbstractBaseUser, identifier: str, email: str, authority: str
) -> PlanPreparation | None:
    """Queue a staging order's preparation with its request, or ``None`` if an operation is
    active. Raises ``Server.DoesNotExist`` when a concurrent request removed the server."""
    try:
        preparation = lifecycle.queue(
            PlanPreparation, server, action=Action.TLS_STAGING, requested_by=user
        )
    except OperationBusy:
        return None
    StagingRequest.objects.create(
        preparation=preparation,
        identifier=identifier,
        email=email,
        authority=authority,
        terms_accepted=True,
    )
    return preparation


@recovers_first
@transaction.atomic
def request_issuance_preparation(
    server: Server, user: AbstractBaseUser, identifier: str, email: str
) -> PlanPreparation | None:
    """Queue a production order's preparation with its request, or ``None`` if an operation
    is active. Raises ``Server.DoesNotExist`` when a concurrent request removed the server."""
    try:
        preparation = lifecycle.queue(
            PlanPreparation, server, action=Action.TLS_ISSUANCE, requested_by=user
        )
    except OperationBusy:
        return None
    IssuanceRequest.objects.create(
        preparation=preparation,
        identifier=identifier,
        email=email,
        terms_accepted=True,
    )
    return preparation


@recovers_first
def request_activation_preparation(
    server: Server, user: AbstractBaseUser, identifier: str
) -> PlanPreparation | None:
    """Queue an HTTPS activation's preparation with its request, or ``None`` if an
    operation is active. Raises ``Server.DoesNotExist`` when a concurrent request removed
    the server."""
    with transaction.atomic():
        try:
            preparation = lifecycle.queue(
                PlanPreparation, server, action=Action.TLS_ACTIVATION, requested_by=user
            )
        except OperationBusy:
            return None
        ActivationRequest.objects.create(preparation=preparation, identifier=identifier)
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


@recovers_first
def request_readiness_preparation(
    server: Server, user: AbstractBaseUser, identifier: str
) -> PlanPreparation | None:
    """Queue a readiness review's preparation, or ``None`` if an operation is active.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    with transaction.atomic():
        try:
            preparation = lifecycle.queue(
                PlanPreparation, server, action=Action.TLS_READINESS, requested_by=user
            )
        except OperationBusy:
            return None
        TlsRequest.objects.create(preparation=preparation, identifier=identifier)
    return preparation


def read_tls_plans(server: Server) -> ServerPlans:
    return read_plans(server, TLS_ACTIONS)


@recovers_first
def read_site_readiness(server: Server, identifier: str) -> ServerPlans:
    """The server's TLS readiness plans for one site, newest first."""
    family = list(READINESS_ACTIONS)
    preparations = with_plans(
        PlanPreparation.objects.filter(
            server=server, action__in=family, tls_request__identifier=identifier
        )
    )
    active = lifecycle.active_operation(server)
    refreshes = index_changes(server.pk)
    return ServerPlans(
        [view(preparation, refreshes) for preparation in preparations],
        other_active=active is not None and not in_family(active, family),
    )
