"""The Laravel cache store before Barectl turned a site's object cache on (#393).

The value is a controller-side record from the review that last turned this site's cache on,
never a guess from the server. A fresh controller has no such record, so turning the cache
off refuses to overwrite the store it cannot name. The record is kept in the applied review's
immutable document, which the change engine retains for its audit; no migration or duplicate
per-site state exists.
"""

from dataclasses import dataclass

from operations.models import ChangeRun, RemoteOperation, Verification
from servers.models import Server

from .instance import SLUG


@dataclass(frozen=True)
class StorePreimage:
    known: bool
    present: bool
    value: str

    def document(self) -> dict[str, object]:
        if not self.known:
            return {}
        return {
            "cache_store_known": True,
            "cache_store_present": self.present,
            "cache_store": self.value,
        }


def previous_store(server: Server, identifier: str) -> StorePreimage:
    """The store last recorded before this site's cache turned on, if this device has it."""
    run = (
        ChangeRun.objects.filter(
            server=server,
            review__kind_slug=SLUG,
            review__document__identifier=identifier,
            review__document__enabled=True,
            status=RemoteOperation.Status.SUCCEEDED,
            verification=Verification.PASSED,
        )
        .select_related("review")
        .order_by("-finished_at", "-pk")
        .first()
    )
    if run is None:
        return StorePreimage(False, True, "")
    document = run.review.document
    present = document.get("previous_store_present")
    value = document.get("previous_store")
    if type(present) is not bool or not isinstance(value, str):
        return StorePreimage(False, True, "")
    return StorePreimage(True, present, value)
