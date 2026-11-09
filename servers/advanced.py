"""The Advanced page's distinct host checks and distribution package rows."""

from discovery.models import ObservationOutcome
from discovery.presentation import Fact, ShownComponent, SnapshotPresentation

STACK_TABS = (
    ("web", "Web server"),
    ("services", "Services"),
    ("php", "PHP versions"),
    ("catalog", "Software catalog"),
)

_HOST_CHECK_LABELS = {
    "APT series": "APT version",
    "dpkg series": "Package manager version",
    "systemd series": "System service manager version",
    "Privilege": "Administrator access",
    "Ports 80/443 listeners": "Web port listeners",
    "Hosting panel paths": "Hosting panels",
    "Nix installation": "Nix installation",
    "Nix build-user ID range": "Nix user IDs",
    "Required tools": "Required tools",
    "Clock synchronization": "Time synchronization",
    "APT background activity": "Package updates running",
}


def host_checks(presented: SnapshotPresentation | None) -> tuple[Fact, ...]:
    if presented is None or presented.standing is None:
        return ()
    return tuple(
        Fact(_HOST_CHECK_LABELS[label], value)
        for label, value in presented.standing.evidence
        if label in _HOST_CHECK_LABELS
    )


def package_checks(presented: SnapshotPresentation | None) -> tuple[ShownComponent, ...]:
    if presented is None:
        return ()
    return tuple(
        row
        for row in presented.components
        if row.package.outcome != ObservationOutcome.ABSENT
        or row.service.outcome != ObservationOutcome.ABSENT
    )


def setup_components(presented: SnapshotPresentation | None) -> tuple[Fact, ...]:
    if presented is None or presented.standing is None:
        return ()
    labels = {
        "Catalog realisation": "Runtime tools",
        "Caddy": "Web server",
        "journald": "Persistent logs",
    }
    return tuple(
        Fact(labels.get(stage, stage), result.capitalize())
        for stage, result in presented.standing.foundation
        if stage not in {"Nix", "Verify"}
    )
