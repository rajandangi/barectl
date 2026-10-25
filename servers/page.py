"""The server page's one status line and at most one next-action banner.

The words describe stored observations. They are never a second eligibility check: the
review, the native lock and fresh revalidation still decide whether a change can run
(docs/dashboard-workflows.md#connection-states-and-next-actions).
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from django.urls import reverse
from django.utils import timezone

from bootstrap.foundation import SLUG as HOST_FOUNDATION
from bootstrap.standing import Standing

from .discovery_state import DiscoveryState, Status

READY = "Ready"
NEEDS_SETUP = "Needs setup"
CHECKING = "Checking…"
CANNOT_BE_MANAGED = "Cannot be managed"
CONNECTION_FAILED = "Connection failed"
NOT_CHECKED = "Not checked yet"

# A check still queued after a minute may need the worker started. docs/ssh-connections.md
# says the page reports the worker as unavailable after ten minutes.
QUEUE_HELP_AFTER = timedelta(minutes=1)


@dataclass(frozen=True)
class BannerAction:
    """One control in the banner, either a link or a CSRF-protected POST."""

    label: str
    url: str
    primary: bool = False
    post: bool = False
    kind: str = ""


@dataclass(frozen=True)
class Banner:
    """The one thing the server page asks the operator to do next."""

    kind: str
    title: str
    note: str = ""
    reasons: tuple[str, ...] = ()
    actions: tuple[BannerAction, ...] = ()
    show_queue: bool = False
    queued_at: datetime | None = None
    worker_unavailable: bool = False


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


def banner(
    state: DiscoveryState,
    *,
    host_challenge: bool,
    can_set_up: bool,
    can_request_check: bool,
    can_edit: bool,
    attention: tuple[object, ...] = (),
) -> Banner | None:
    """The most urgent next step, or ``None`` when the page already offers it."""
    pending = _pending_banner(
        state,
        host_challenge=host_challenge,
        can_request_check=can_request_check,
        can_edit=can_edit,
    )
    if pending is not None:
        return pending
    return _result_banner(
        state,
        can_set_up=can_set_up,
        can_request_check=can_request_check,
        attention=attention,
    )


def _pending_banner(
    state: DiscoveryState,
    *,
    host_challenge: bool,
    can_request_check: bool,
    can_edit: bool,
) -> Banner | None:
    """The step before a result: identity, a running check, or a failed one."""
    if host_challenge:
        return Banner(
            "confirm",
            "Confirm this is your server",
            "Find this fingerprint in your provider's console or serial console, then paste "
            "it below.",
        )
    if state.checking:
        attempt = state.attempt
        queued_for = timezone.now() - attempt.queued_at if attempt is not None else timedelta()
        return Banner(
            "checking",
            "Checking the connection…",
            show_queue=queued_for > QUEUE_HELP_AFTER,
            queued_at=attempt.queued_at if attempt is not None else None,
            worker_unavailable=attempt is not None and attempt.worker_unavailable,
        )
    if not state.alias_usable:
        return Banner(
            "failed",
            CONNECTION_FAILED,
            "The saved SSH alias is no longer a usable Host entry on this computer.",
            actions=(
                BannerAction("Edit connection", reverse("server_edit", args=[state.server.pk])),
            ),
        )
    if state.status != Status.FAILED:
        return None
    failure = (
        state.attempt.failure
        if state.attempt is not None and state.attempt.failure
        else "Barectl could not connect to this server."
    )
    actions: list[BannerAction] = []
    if can_request_check:
        actions.append(
            BannerAction(
                "Check again",
                reverse("server_verify", args=[state.server.pk]),
                primary=True,
                post=True,
            )
        )
    if can_edit:
        actions.append(
            BannerAction("Edit connection", reverse("server_edit", args=[state.server.pk]))
        )
    return Banner("failed", CONNECTION_FAILED, failure, actions=tuple(actions))


def _result_banner(
    state: DiscoveryState,
    *,
    can_set_up: bool,
    can_request_check: bool,
    attention: tuple[object, ...],
) -> Banner | None:
    """The result after a check: ready, unreadable, or needing setup."""
    snapshot = state.snapshot
    standing = snapshot.collected.standing if snapshot is not None else None
    if standing is None:
        actions = (
            (
                BannerAction(
                    "Check the connection",
                    reverse("server_verify", args=[state.server.pk]),
                    primary=True,
                    post=True,
                ),
            )
            if can_request_check
            else ()
        )
        return Banner(
            "check",
            "Check the connection",
            "Barectl has not read this server yet.",
            actions=actions,
        )
    if standing.standing == Standing.NOT_MANAGEABLE:
        return Banner(
            "cannot_manage",
            "Barectl cannot manage this server",
            reasons=standing.reasons,
        )
    if standing.standing != Standing.TARGET_STACK:
        actions = (
            (
                BannerAction(
                    "Set up server",
                    reverse("server_change_prepare", args=[state.server.pk]),
                    primary=True,
                    post=True,
                    kind=HOST_FOUNDATION,
                ),
            )
            if can_set_up
            else ()
        )
        note = (
            "Barectl installs the web server and the tools it uses on this host."
            if can_set_up
            else "An operator with permission to prepare changes can set up this server."
        )
        return Banner("setup", "Ready to set up", note, actions=actions)
    for item in attention:
        action_url = getattr(item, "action_url", "")
        if action_url:
            return Banner(
                "attention",
                str(getattr(item, "action", "")),
                actions=(BannerAction(str(getattr(item, "action", "")), str(action_url)),),
            )
    return None
