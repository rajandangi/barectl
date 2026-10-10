"""Operator requests for native Node runtimes (docs/node-runtimes-native-design.md)."""

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction

from bootstrap.models import Action, PlanPreparation
from bootstrap.services import request_preparation
from operations.lifecycle import recovers_first
from servers.models import Server
from sites.names import valid_identifier

from . import catalog, permissions
from .models import RuntimeRequest


@recovers_first
def request_runtime_preparation(
    server: Server, user: AbstractBaseUser, version: str, *, identifier: str = ""
) -> PlanPreparation | None:
    if version not in catalog.VERSIONS or (identifier and not valid_identifier(identifier)):
        raise ValueError("Select a reviewed exact Node LTS runtime and valid site.")
    if not permissions.authorized(user.pk, identifier, "prepare"):
        return None
    with transaction.atomic():
        preparation = request_preparation(server, user, Action.NODE_RUNTIME)
        if preparation is not None:
            RuntimeRequest.objects.create(
                preparation=preparation, version=version, identifier=identifier
            )
        return preparation
