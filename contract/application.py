"""The application-surface section of the native contract (docs/contracts.md, ADR 0042).

Operators and scripts address Barectl through permission names, URL names, management
commands and documented environment variables. Every entry below is read from the module
that owns it: permission codenames come from each model's own ``Meta``, URL names come
from Django's URL resolver after the apps load, commands are checked against Django's
command registry, and the environment names come from one constant in ``config.settings``.
No second list repeats a full name.
"""

from typing import TYPE_CHECKING, Final

from django.contrib.auth import get_permission_codename

if TYPE_CHECKING:
    from collections.abc import Iterable

    from django.db import models

# README.md#run-locally, README.md#operator-accounts, README.md#development,
# docs/upgrade.md, docs/hosting.md and docs/frontend-assets.md promise these commands.
# Built-ins and django_tasks_db's db_worker join the dashboard's barectl_upgrade.
DOCUMENTED_COMMANDS: Final = (
    "barectl_upgrade",
    "changepassword",
    "check",
    "collectstatic",
    "createsuperuser",
    "db_worker",
    "makemigrations",
    "migrate",
    "runserver",
    "showmigrations",
    "test",
)

# README.md#operator-accounts documents starting a connection check with this model's
# default add permission; it promises no change, delete or view permission for it.
DISCOVERY_ATTEMPT_ACTIONS: Final = ("add",)


def _model_permissions(model: type[models.Model], actions: Iterable[str]) -> list[str]:
    """``model``'s permission names for ``actions``, from its own ``Meta``."""
    options = model._meta
    return [f"{options.app_label}.{get_permission_codename(action, options)}" for action in actions]


def _engine_permissions() -> list[str]:
    """The change engine's six scope permissions, named by the model that declares them."""
    from operations.models import ChangeReview

    options = ChangeReview._meta
    return [f"{options.app_label}.{codename}" for codename, _label in options.permissions]


def _permissions() -> list[str]:
    from discovery.models import DiscoveryAttempt
    from discovery.presentation import VIEW_SITES
    from servers.models import Server

    return sorted(
        {
            *_engine_permissions(),
            *_model_permissions(Server, Server._meta.default_permissions),
            *_model_permissions(DiscoveryAttempt, DISCOVERY_ATTEMPT_ACTIONS),
            VIEW_SITES,
        }
    )


def _url_names() -> list[str]:
    """Every named route in the URLconf, namespaced when it lives in a namespace."""
    from django.urls import URLPattern, URLResolver, get_resolver

    def walk(patterns: Iterable[URLPattern | URLResolver], namespace: str = "") -> list[str]:
        names: list[str] = []
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                prefix = f"{pattern.namespace}:" if pattern.namespace else ""
                names.extend(walk(pattern.url_patterns, f"{namespace}{prefix}"))
            elif pattern.name:
                names.append(f"{namespace}{pattern.name}")
        return names

    return sorted(walk(get_resolver().url_patterns))


def _commands() -> list[str]:
    """The documented commands this installation actually provides."""
    from django.core.management import get_commands

    available = get_commands()
    return sorted(name for name in DOCUMENTED_COMMANDS if name in available)


def _environment() -> list[str]:
    from config.settings import DOCUMENTED_ENVIRONMENT

    return sorted(DOCUMENTED_ENVIRONMENT)


def build() -> dict[str, object]:
    """Permissions, URL names, commands and environment variables as one mapping."""
    return {
        "permissions": _permissions(),
        "url_names": _url_names(),
        "commands": _commands(),
        "environment": _environment(),
    }
