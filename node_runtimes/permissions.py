"""Scoped runtime authority (docs/node-runtimes-native-design.md)."""

from typing import Literal

from django.contrib.auth.models import User

from bootstrap.actions import BOOTSTRAP
from operations.lifecycle import OperationRefused
from sites.handler import AUTHORITY as SITE

from .models import RunNodeRuntime, RuntimeRequest

type Stage = Literal["view", "prepare", "apply"]


def required(identifier: str, stage: Stage) -> tuple[str, ...]:
    base = {"view": BOOTSTRAP.view, "prepare": BOOTSTRAP.prepare, "apply": BOOTSTRAP.apply}
    site = {"view": SITE.view, "prepare": SITE.prepare, "apply": SITE.apply}
    return tuple(dict.fromkeys((*base[stage], *(site[stage] if identifier else ()))))


def operation_required(operation_id: int, stage: Stage) -> tuple[str, ...] | None:
    identifier = (
        RuntimeRequest.objects.filter(preparation_id=operation_id)
        .values_list("identifier", flat=True)
        .first()
    )
    if identifier is None:
        identifier = (
            RunNodeRuntime.objects.filter(run_id=operation_id)
            .values_list("identifier", flat=True)
            .first()
        )
    return None if identifier is None else required(identifier, stage)


def authorized(user_id: int | None, identifier: str, stage: Stage) -> bool:
    if user_id is None:
        return False
    current = User.objects.filter(pk=user_id, is_active=True).first()
    return current is not None and current.has_perms(required(identifier, stage))


def admit(user_id: int | None, identifier: str, stage: Stage) -> None:
    if not authorized(user_id, identifier, stage):
        raise OperationRefused("The requesting account lacks current scoped Node permissions.")
