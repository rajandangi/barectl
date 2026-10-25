"""A WordPress site's **Settings > Scheduled tasks** section (Phase C #357).

Opening the section makes no SSH connection: it renders the latest observation's projection.
Preparing a change queues one Site review; the confirm screen and run progress are the
shared change screens.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from bootstrap.standing import Standing
from discovery.models import SiteState
from discovery.presentation import VIEW_SITES
from discovery.snapshot import ObservedSite
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from sites.names import valid_identifier

from . import presentation
from .change import SLUG
from .forms import ScheduleForm

CHANGED = "The saved connection changed. Refresh and prepare a new review."
BUSY = "Wait for the current operation before preparing this review."


def _site(state: DiscoveryState, identifier: str) -> ObservedSite | None:
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier),
        None,
    )


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    site = _site(state, identifier)
    snapshot = state.snapshot
    standing = snapshot.collected.standing if snapshot is not None else None
    complete = (
        site is not None
        and site.application == "wordpress"
        and not site.application_problem
        and site.state == SiteState.MANAGED
        and site.file.startswith("/etc/caddy/sites/")
        and standing is not None
        and standing.standing == Standing.TARGET_STACK
    )
    lines = (
        presentation.lines(snapshot.collected, identifier, snapshot.collected_at)
        if snapshot is not None and site is not None and site.application == "wordpress"
        else ()
    )
    allowed = (
        complete
        and state.can_prepare_changes
        and not services.read_changes(server).polling
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
    )
    return {
        "scheduled_tasks": lines[0] if lines else None,
        "scheduled_tasks_can_prepare": allowed,
        "scheduled_tasks_form": ScheduleForm(),
        "scheduled_tasks_ready": complete,
    }


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_schedule(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server, identifier, request.user)
    form = ScheduleForm(request.POST)
    if not context["scheduled_tasks_can_prepare"] or not form.is_valid():
        messages.error(
            request,
            "Choose an action on a current, complete WordPress site with no other change "
            "in progress.",
        )
        return redirect("site_settings", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            SLUG,
            inputs={
                "version": 1,
                "identifier": identifier,
                "state": form.cleaned_data["state"],
            },
        )
    except OperationRefused, ValueError:
        messages.error(request, CHANGED)
        return redirect("site_settings", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, BUSY)
        return redirect("site_settings", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
