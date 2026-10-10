"""docs/adr/0035-one-change-engine-with-effect-derived-consent.md"""

from collections.abc import Iterable
from dataclasses import dataclass

from django.db import models


class Consent(models.TextChoices):
    READ = "read", "Read"
    SITE = "site", "Site"
    SHARED = "shared", "Shared"
    DESTRUCTIVE = "destructive", "Destructive"


@dataclass(frozen=True)
class Effect:
    """One effect a review declares; a change kind never declares its consent level."""

    text: str
    # The one site the effect is confined to, or ``None`` for a server-wide service, a
    # PHP-FPM master or Caddy, which can serve other sites.
    site: str | None = None
    data_loss: bool = False


# The permission an account needs to apply a change at each level; a Read change is
# never applied.
APPLY_PERMISSIONS = {
    Consent.SITE: "operations.apply_site_change",
    Consent.SHARED: "operations.apply_shared_change",
    Consent.DESTRUCTIVE: "operations.apply_destructive_change",
}


def consent(effects: Iterable[Effect]) -> Consent:
    declared = list(effects)
    if not declared:
        return Consent.READ
    if any(effect.data_loss for effect in declared):
        return Consent.DESTRUCTIVE
    sites = {effect.site for effect in declared}
    if None in sites or len(sites) > 1:
        return Consent.SHARED
    return Consent.SITE
