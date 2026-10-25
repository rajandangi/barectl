"""The server page's one status line and at most one next action (docs/dashboard-workflows.md).

The words describe stored observations. They are never a second eligibility check: the
review, the native lock and fresh revalidation still decide whether a change can run.
"""

from dataclasses import dataclass

from django.urls import reverse

from bootstrap.standing import Standing

from .discovery_state import DiscoveryState, Status

READY = "Ready"
NEEDS_SETUP = "Needs setup"
CHECKING = "Checking…"
CANNOT_BE_MANAGED = "Cannot be managed"
CONNECTION_FAILED = "Connection failed"
NOT_CHECKED = "Not checked yet"


@dataclass(frozen=True)
class NextAction:
    """The one thing the page asks the operator to do next."""

    label: str
    url: str
    note: str = ""
    post: bool = False


def status_line(state: DiscoveryState) -> str:
    if state.checking:
        return CHECKING
    if state.status == Status.FAILED:
        return CONNECTION_FAILED
    if not state.alias_usable:
        return CONNECTION_FAILED
    snapshot = state.snapshot
    if snapshot is None:
        return NOT_CHECKED
    standing = snapshot.collected.standing
    if standing is None:
        return NOT_CHECKED
    if standing.standing == Standing.NOT_MANAGEABLE:
        return CANNOT_BE_MANAGED
    if standing.standing == Standing.TARGET_STACK:
        return READY
    return NEEDS_SETUP


def next_action(
    state: DiscoveryState,
    *,
    host_challenge: bool,
    can_set_up: bool,
    attention: tuple[object, ...] = (),
) -> NextAction | None:
    """The most urgent action, or ``None`` when the page already offers it."""
    connection = _connection_action(state, host_challenge=host_challenge)
    if connection is not None:
        return connection
    if state.checking:
        return None
    snapshot = state.snapshot
    standing = snapshot.collected.standing if snapshot is not None else None
    if standing is None:
        return NextAction(
            "Check the connection",
            f"{reverse('server_settings', args=[state.server.pk])}#connection",
            "Barectl has not read this server yet.",
        )
    if standing.standing == Standing.NOT_MANAGEABLE:
        return None
    if standing.standing != Standing.TARGET_STACK:
        if not can_set_up:
            return None
        return NextAction(
            "Set up server",
            reverse("server_setup", args=[state.server.pk]),
            "Barectl installs the web server and the tools it uses on this host.",
            post=True,
        )
    for item in attention:
        action_url = getattr(item, "action_url", "")
        if action_url:
            return NextAction(str(getattr(item, "action", "")), action_url)
    return None


def _connection_action(state: DiscoveryState, *, host_challenge: bool) -> NextAction | None:
    """The one action a server whose connection is not established needs."""
    if host_challenge:
        return NextAction(
            "Confirm this is your server",
            f"{reverse('server_settings', args=[state.server.pk])}#connection",
            "Barectl needs the fingerprint from your provider before it connects.",
        )
    if not state.alias_usable:
        return NextAction(
            "Edit connection",
            reverse("server_edit", args=[state.server.pk]),
            "The saved SSH alias is no longer a usable Host entry on this computer.",
        )
    if state.status == Status.FAILED:
        return NextAction(
            "Check again",
            f"{reverse('server_settings', args=[state.server.pk])}#connection",
            "The last check could not connect.",
        )
    return None
