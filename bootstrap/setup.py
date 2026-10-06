"""The Setup section's hosting summary (docs/bootstrap.md#review-apply-and-check).

The summary classifies the components the last complete observation reported. It reflects
recorded evidence only: a suggested profile still needs fresh preparation, review and
admission, and an unread component is never treated as absent.
"""

from dataclasses import dataclass
from enum import StrEnum, nonmember

from discovery.models import ObservationOutcome, WebStackComponent
from discovery.presentation import UNINSPECTED, ShownComponent, SnapshotPresentation

from .models import Action


class SetupState(StrEnum):
    """How the recorded evidence describes one hosting component, in the pages' wording."""

    do_not_call_in_templates = nonmember(True)

    REFRESH = "Refresh required"
    MISSING = "Observed absent"
    READY = "Observed installed"
    NOT_FOLLOWING = "Not following the profile"
    PARTIAL = "Package installed, service not found"
    UNINSPECTABLE = "Inspection unavailable"
    UNKNOWN = "Not observed"


@dataclass(frozen=True)
class SetupComponent:
    label: str
    state: SetupState
    # The reviewed profile that would install the component, when one exists.
    action: Action
    # The recorded package and service lines, so the operator sees the evidence.
    evidence: tuple[str, ...]
    note: str


_PROFILES = (
    (WebStackComponent.NGINX, Action.NGINX),
    (WebStackComponent.PHP_FPM, Action.PHP),
    (WebStackComponent.MARIADB, Action.MARIADB),
    (WebStackComponent.POSTGRESQL, Action.POSTGRESQL),
)

_NOTES = {
    SetupState.REFRESH: (
        "Refresh the connection to inspect this component before deciding whether to install it."
    ),
    SetupState.READY: (
        "Packages and service units were observed. This is recorded evidence, not live "
        "health; the profile would not upgrade or customize it."
    ),
    SetupState.PARTIAL: (
        "The packages were observed installed but no service unit was found. Review the "
        "profile; it enables and starts the service without installing packages, or refuses "
        "an unexpected state."
    ),
    SetupState.UNINSPECTABLE: (
        "Barectl could not read this component, so it is not known to be missing. Inspect the "
        "unavailable evidence under Advanced before installing anything."
    ),
    SetupState.UNKNOWN: "This component was not part of the collected evidence.",
}


def summary(presentation: SnapshotPresentation | None) -> tuple[SetupComponent, ...]:
    """Every supported hosting component with its observed state and reviewed profile."""
    if presentation is None:
        return tuple(
            SetupComponent(
                component.label, SetupState.REFRESH, action, (), _NOTES[SetupState.REFRESH]
            )
            for component, action in _PROFILES
        )
    found = {item.label: item for item in presentation.components}
    return tuple(
        _component(component.label, action, found.get(component.label))
        for component, action in _PROFILES
    )


def _component(label: str, action: Action, shown: ShownComponent | None) -> SetupComponent:
    if shown is None:
        return SetupComponent(label, SetupState.UNKNOWN, action, (), _NOTES[SetupState.UNKNOWN])
    package, service = shown.package, shown.service
    if package.outcome == ObservationOutcome.ABSENT:
        state = SetupState.MISSING
        note = (
            f"{label} packages were observed absent. Review the {action.label} before applying "
            "it; preparing and reviewing change nothing."
        )
    elif package.outcome in UNINSPECTED or service.outcome in UNINSPECTED:
        state = SetupState.UNINSPECTABLE
        note = _NOTES[SetupState.UNINSPECTABLE]
    elif package.outcome == ObservationOutcome.OBSERVED and not shown.managed:
        state = SetupState.NOT_FOLLOWING
        note = (
            f"The installed {label} packages do not follow the release's bootstrap profile. "
            f"{' '.join(shown.deviations)}"
        )
    elif package.outcome == ObservationOutcome.OBSERVED and (
        service.outcome == ObservationOutcome.OBSERVED
    ):
        state = SetupState.READY
        note = _NOTES[SetupState.READY]
    elif package.outcome == ObservationOutcome.OBSERVED:
        state = SetupState.PARTIAL
        note = _NOTES[SetupState.PARTIAL]
    else:
        state = SetupState.UNKNOWN
        note = _NOTES[SetupState.UNKNOWN]
    return SetupComponent(label, state, action, (*package.lines, *service.lines), note)
