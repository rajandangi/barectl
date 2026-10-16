"""docs/adr/0035-one-change-engine-with-effect-derived-consent.md: consent is derived from
the effects a review declares, never chosen by the kind that declares them."""

from collections.abc import Sequence
from dataclasses import dataclass

from django.db import models

from .models import (
    CHANGE_DESTRUCTIVE,
    CHANGE_SHARED,
    CHANGE_SITE,
    VIEW_CHANGES,
    Consent,
)


class Scope(models.TextChoices):
    """Whose resources a declared effect touches."""

    # Exactly one site, which the effect names.
    SITE = "site", "One site"
    # Resources sites or operators share: the Caddy configuration, the server's shared
    # native change evidence. The effect names the sites it reaches, if any.
    SHARED = "shared", "Shared resources"
    # The server's operating state as a whole, such as its foundation or a restart.
    SERVER = "server", "The whole server"


@dataclass(frozen=True)
class DeclaredEffect:
    """One effect a review declares: what applying will do, and whose resources it touches."""

    scope: Scope
    text: str
    # The sites the effect reaches, by identifier; a SITE effect names exactly one.
    sites: tuple[str, ...] = ()
    destroys_data: bool = False


def affected_sites_of(effects: Sequence[DeclaredEffect]) -> tuple[str, ...]:
    return tuple(sorted({site for effect in effects for site in effect.sites}))


def consent_of(effects: Sequence[DeclaredEffect]) -> Consent:
    """docs/adr/0035-one-change-engine-with-effect-derived-consent.md"""
    if not effects:
        return Consent.READ
    if any(effect.destroys_data for effect in effects):
        return Consent.DESTRUCTIVE
    if any(effect.scope is Scope.SERVER for effect in effects):
        return Consent.SHARED
    if (
        any(effect.scope is Scope.SHARED for effect in effects)
        or len(affected_sites_of(effects)) > 1
    ):
        return Consent.SHARED
    return Consent.SITE


CONSENT_PERMISSIONS: dict[Consent, tuple[str, ...]] = {
    Consent.READ: (VIEW_CHANGES,),
    Consent.SITE: (VIEW_CHANGES, CHANGE_SITE),
    Consent.SHARED: (VIEW_CHANGES, CHANGE_SHARED),
    Consent.DESTRUCTIVE: (VIEW_CHANGES, CHANGE_DESTRUCTIVE),
}

# Preparing any change is reviewing, which a viewer may not do; the derived consent's own
# permission is rechecked by the worker once the review exists.
PREPARE_PERMISSIONS: tuple[str, ...] = (
    "servers.view_server",
    VIEW_CHANGES,
    CHANGE_SITE,
)
