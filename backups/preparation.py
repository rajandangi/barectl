"""The requirement sets the Backups cards ask the preparation gate (spec #507, #512).

A managed site, or a gated site whose only missing item is the maintenance gate, is the
Backups section's longstanding readiness shape. A gated or paused site is withheld from a
change that assumes an open site and offered reopening instead.
"""

from dataclasses import replace

from operations import preparation
from sites.bodies.common import SITE_GATED

BASE = replace(
    preparation.SITE,
    state=None,
    completes=SITE_GATED,
    open_site=True,
)
REOPEN = replace(preparation.SITE, state=None, completes=SITE_GATED, gated=True)
ENABLE = replace(BASE, needs=BASE.needs | {preparation.Need.SECRET})
DESTRUCTIVE = replace(BASE, needs=BASE.needs | {preparation.Need.DESTRUCTIVE})
EXPORT = replace(BASE, needs=BASE.needs | {preparation.Need.SHARED})
