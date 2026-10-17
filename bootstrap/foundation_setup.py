"""Setup steps project current observations and immutable change records."""

from dataclasses import dataclass

from operations.lifecycle import connection_current
from operations.models import ChangeReview
from servers.discovery_state import DiscoveryState, Status

from .foundation import SLUG
from .standing import Standing

LABELS = ("Connect", "Check host", "Review", "Apply and verify")


@dataclass(frozen=True)
class SetupStep:
    label: str
    status: str


@dataclass(frozen=True)
class SetupJourney:
    current: int
    label: str
    complete: bool
    steps: tuple[SetupStep, ...]


def project(state: DiscoveryState) -> SetupJourney:
    current = 1
    complete = False
    if state.status is Status.VERIFIED:
        current = 2
        snapshot = state.snapshot
        standing = snapshot.collected.standing if snapshot else None
        if standing and state.snapshot_notice is None and state.can_prepare_changes:
            current = 3
            if standing.standing is Standing.TARGET_STACK:
                current, complete = 4, True
            else:
                review = (
                    ChangeReview.objects.filter(preparation__server=state.server, kind_slug=SLUG)
                    .select_related("preparation__connection", "preparation__server")
                    .order_by("-pk")
                    .first()
                )
                if (
                    review is not None
                    and review.preparation is not None
                    and connection_current(review.preparation)
                    and review.eligible
                ):
                    current = 4
    return SetupJourney(
        current,
        LABELS[current - 1],
        complete,
        tuple(
            SetupStep(
                label,
                "complete"
                if complete or index < current
                else "current"
                if index == current
                else "",
            )
            for index, label in enumerate(LABELS, 1)
        ),
    )
