"""A site's PHP version is chosen in its Settings and applied through the change engine.

docs/dashboard-workflows.md, docs/runtimes.md#site-php-selection. The old Runtime section
is gone; its selection form lives in Settings, and a version this server does not have yet
is offered as Step 1 through Add runtime, keeping the choice for the switch that follows.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from bootstrap.standing import Standing
from discovery.models import ObservationOutcome, SiteState
from discovery.presentation import VIEW_SITES
from discovery.snapshot import ObservedSite
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from runtimes.change import SLUG as ADD_RUNTIME_SLUG
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server

from . import continuation, prerequisites
from .names import valid_identifier
from .observation import PHP_TRANSITION_INCOMPLETE
from .php_change import CHOICES, SLUG
from .php_forms import SitePhpForm


def _site(state: DiscoveryState, identifier: str) -> ObservedSite | None:
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier),
        None,
    )


def choices_for(state: DiscoveryState) -> tuple[str, ...]:
    """The installed PHP versions whose service the current observation verified."""
    return tuple(entry for entry in prerequisites.verified_versions(state) if entry in CHOICES)


def switch_choices(
    state: DiscoveryState, *, current: str, incomplete: bool
) -> tuple[prerequisites.PhpChoice, ...]:
    """The other catalog versions; a partly applied switch also offers its current one."""
    choices = prerequisites.php_choices(state)
    if incomplete:
        return choices
    return tuple(choice for choice in choices if choice.entry != current)


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    site = _site(state, identifier)
    current = site.php_version if site else ""
    incomplete = (
        site is not None
        and site.state == SiteState.PARTLY_APPLIED
        and site.missing == (PHP_TRANSITION_INCOMPLETE,)
    )
    choices = switch_choices(state, current=current, incomplete=incomplete)
    allowed = (
        site is not None
        and snapshot is not None
        and snapshot.collected.standing is not None
        and snapshot.collected.standing.standing == Standing.TARGET_STACK
        and snapshot.collected.sites.outcome == ObservationOutcome.OBSERVED
        and site.outcome == ObservationOutcome.OBSERVED
        and site.file == f"/etc/caddy/sites/{identifier}.caddy"
        and (site.state == SiteState.MANAGED or incomplete)
    )
    return {
        "php_runtime_incomplete": incomplete,
        "php_runtime_selection": current,
        "site_php_current": current,
        "site_php_current_label": prerequisites.number_label(current) if current else "",
        "site_php_choices": tuple(
            {
                "entry": choice.entry,
                "label": choice.version_label,
                "installed": choice.installed,
                "download": (
                    "" if choice.installed else prerequisites.download_label(choice.download_size)
                ),
            }
            for choice in choices
        ),
        "site_php_can_prepare": bool(choices)
        and allowed
        and state.can_prepare_changes
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
        and not services.read_changes(server).polling,
    }


def _remember_step(
    request: HttpRequest,
    server: Server,
    preparation_id: int,
    identifier: str,
    selection: str,
) -> None:
    continuation.remember(
        request,
        continuation.CreationStep(
            preparation_id=preparation_id,
            server_id=server.pk,
            platform="switch_php",
            kind=ADD_RUNTIME_SLUG,
            selection=selection,
            step_title=(
                f"Step 1 of 2: add {prerequisites.version_label(selection)} to this server"
            ),
            continue_label="Continue to switch the site's PHP version",
            answers={"identifier": identifier, "selection": selection},
        ),
    )


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_php(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    state = server_state(server)
    site = _site(state, identifier)
    current = site.php_version if site else ""
    incomplete = (
        site is not None
        and site.state == SiteState.PARTLY_APPLIED
        and site.missing == (PHP_TRANSITION_INCOMPLETE,)
    )
    context = context_for_site(server, identifier, request.user)
    choices = switch_choices(state, current=current, incomplete=incomplete)
    form = SitePhpForm(request.POST, choices=tuple(choice.entry for choice in choices))
    if not context["site_php_can_prepare"] or not form.is_valid():
        messages.error(request, "Choose another PHP version from a fresh check of this site.")
        return redirect("site_settings", pk=pk, identifier=identifier)
    selection = str(form.cleaned_data["selection"])
    try:
        if selection in choices_for(state):
            queued = services.request_prepare(
                server,
                request.user,
                SLUG,
                inputs={"version": 1, "identifier": identifier, "selection": selection},
            )
        else:
            queued = services.request_prepare(
                server,
                request.user,
                ADD_RUNTIME_SLUG,
                inputs={"version": 1, "selection": selection},
            )
            if queued is not None:
                _remember_step(request, server, queued.pk, identifier, selection)
    except OperationRefused, ValueError:
        messages.error(
            request, "The saved connection changed. Refresh and choose the version again."
        )
        return redirect("site_settings", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current change before preparing another.")
        return redirect("site_settings", pk=pk, identifier=identifier)
    if selection in choices_for(state):
        messages.success(
            request,
            f"Barectl queued switching this site's PHP version to "
            f"{prerequisites.number_label(selection)}. Nothing changes until you confirm it.",
        )
    else:
        messages.success(
            request,
            f"Barectl queued adding {prerequisites.version_label(selection)} to this server. "
            "Your choice is kept for the switch that follows.",
        )
    return redirect("change_detail", operation_id=queued.pk)
