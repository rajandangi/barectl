"""Test support for the security checks (tests never import another test module)."""

from discovery.models import ObservationOutcome
from security.observation import (
    AutoUpdatesState,
    Check,
    FirewallState,
    RestartState,
    SecurityState,
    SshState,
    UpdatesState,
)


def check[T](
    value: T,
    *,
    status: ObservationOutcome = ObservationOutcome.OBSERVED,
    warning: str = "",
) -> Check[T]:
    return Check(status, ("a fixed read",), warning, value)


def blocked[T]() -> Check[T]:
    return Check(
        ObservationOutcome.INACCESSIBLE,
        ("id -u",),
        "Barectl needs root or the authorized passwordless sudo.",
        None,
    )


def ok_state() -> SecurityState:
    return SecurityState(
        firewall=check(
            FirewallState(True, True, "deny", "allow", "deny", True, "on (low)", (), (), True)
        ),
        listeners=check(()),
        ssh=check(SshState("no", "no", "prohibit-password", (22,), (22,), (), "yes")),
        auto_updates=check(AutoUpdatesState(True, "active", "active", False, (), True, "", None)),
        updates=check(UpdatesState(3600, ())),
        restart=check(RestartState(False, ())),
    )
