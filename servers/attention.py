"""A server's Needs attention list: each finding with its one next action."""

from dataclasses import dataclass
from typing import Final

from django.urls import reverse

from automation.presentation import findings as automation_findings
from bootstrap.standing import Standing
from discovery.models import ObservationOutcome, SiteState
from discovery.snapshot import CollectedSnapshot
from sites.bodies.common import NODE_INTERRUPTED, PHP_TRANSITION_INCOMPLETE
from sites.recognition import target_sites

ADMINISTRATION: Final = "Correct it with ordinary administration, then run discovery again."


@dataclass(frozen=True)
class Attention:
    kind: str
    name: str
    finding: str
    action: str
    # Empty when the action is ordinary administration outside Barectl.
    action_url: str = ""
    subject_url: str = ""


def needs_attention(
    server: int, collected: CollectedSnapshot, *, can_set_up: bool
) -> tuple[Attention, ...]:
    """Host findings first, then the sites' and runtimes' own findings."""
    standing = collected.standing
    if standing is None:
        return ()
    host = tuple(
        Attention("Host", "", finding, ADMINISTRATION)
        for finding in (*standing.reasons, *standing.warnings)
    )
    if standing.standing == Standing.INCOMPLETE_FOUNDATION:
        unfinished = ", ".join(stage for stage, state in standing.foundation if state != "present")
        host += (
            Attention(
                "Host foundation",
                "",
                f"Unfinished stages: {unfinished}.",
                *(
                    ("Set up server", reverse("server_setup", args=(server,)))
                    if can_set_up
                    else ("An operator with prepare permission can review the setup change.",)
                ),
            ),
        )
    if standing.standing != Standing.TARGET_STACK:
        return host
    if collected.sites.outcome != ObservationOutcome.OBSERVED:
        return (
            *host,
            Attention(
                "Sites",
                "",
                collected.sites.warning or "The site configuration could not be read.",
                "Inspect the unavailable evidence",
                reverse("server_advanced", args=(server,)),
            ),
            *_runtimes(server, collected),
        )
    return (
        *host,
        *_sites(server, collected),
        *_automation(server, collected),
        *_runtimes(server, collected),
    )


def _sites(server: int, collected: CollectedSnapshot) -> tuple[Attention, ...]:
    items: list[Attention] = []
    for site in target_sites(collected):
        if site.state == SiteState.MANAGED:
            continue
        finding = site.missing[0] if site.missing else site.state.label
        subject_url = reverse("site_detail", args=(server, site.identifier))
        if finding in (PHP_TRANSITION_INCOMPLETE, NODE_INTERRUPTED):
            action = "Finish the runtime change"
            action_url = reverse("site_settings", args=(server, site.identifier))
        else:
            action, action_url = ADMINISTRATION, ""
        items.append(Attention("Site", site.identifier, finding, action, action_url, subject_url))
    return tuple(items)


def _automation(server: int, collected: CollectedSnapshot) -> tuple[Attention, ...]:
    return tuple(
        Attention(
            "Scheduled tasks",
            identifier,
            finding,
            action,
            reverse("site_settings", args=(server, identifier)) + "#scheduled-tasks",
            reverse("site_detail", args=(server, identifier)),
        )
        for identifier, finding, action in automation_findings(collected)
    )


def _runtimes(server: int, collected: CollectedSnapshot) -> tuple[Attention, ...]:
    php = reverse("server_advanced", args=(server,)) + "?tab=php"
    return tuple(
        Attention("PHP runtime", runtime.entry, runtime.problem, "Inspect PHP runtimes", php)
        for runtime in collected.runtimes
        if runtime.problem and runtime.entry.startswith("php")
    )
