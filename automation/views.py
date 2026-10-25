"""A site's **Settings > Scheduled tasks** section (Phase C #357).

WordPress server cron and the Laravel scheduler share the section and the shared change
screens; only the action set and the wording differ. Opening the section makes no SSH
connection: it renders the latest observation's projection.
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

from . import change, presentation, scheduler
from .forms import SCHEDULER_STATES, STATES, ScheduleForm

CHANGED = "The saved connection changed. Refresh and prepare a new review."
BUSY = "Wait for the current operation before preparing this review."
APPLICATIONS = ("wordpress", "laravel")


def _site(state: DiscoveryState, identifier: str) -> ObservedSite | None:
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier),
        None,
    )


def _kind(application: str) -> str:
    return scheduler.SLUG if application == "laravel" else change.SLUG


def _choices(application: str) -> tuple[tuple[str, str], ...]:
    return SCHEDULER_STATES if application == "laravel" else STATES


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    site = _site(state, identifier)
    snapshot = state.snapshot
    standing = snapshot.collected.standing if snapshot is not None else None
    application = site.application if site is not None else ""
    target = (
        site is not None
        and site.file.startswith("/etc/caddy/sites/")
        and standing is not None
        and standing.standing == Standing.TARGET_STACK
    )
    complete = (
        target
        and site is not None
        and site.application in APPLICATIONS
        and not site.application_problem
        and site.state == SiteState.MANAGED
    )
    lines = (
        presentation.lines(
            snapshot.collected,
            identifier,
            snapshot.collected_at,
            presentation.paused_change(server, identifier),
        )
        if snapshot is not None and site is not None and site.application in APPLICATIONS
        else ()
    )
    line = lines[0] if lines else None
    permitted = (
        state.can_prepare_changes
        and not services.read_changes(server).polling
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
    )
    allowed = complete and permitted
    # Stopping is always available while the site's own unit evidence is readable.
    stoppable = target and permitted
    return {
        "scheduled_tasks": line,
        "scheduled_tasks_kind": application,
        "scheduled_tasks_can_prepare": allowed,
        "scheduled_tasks_can_stop": stoppable,
        "scheduled_tasks_can_run": allowed and bool(line and line.on and not line.running),
        "scheduled_tasks_form": ScheduleForm(choices=_choices(application)),
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
    application = str(context["scheduled_tasks_kind"])
    form = ScheduleForm(request.POST, choices=_choices(application))
    state = form.cleaned_data["state"] if form.is_valid() else ""
    allowed = bool(
        context["scheduled_tasks_can_prepare"]
        if state != "off" or application != "laravel"
        else context["scheduled_tasks_can_stop"]
    )
    if not allowed or not form.is_valid():
        messages.error(
            request,
            "Choose an action on a current, complete site with no other change in progress.",
        )
        return redirect("site_settings", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            _kind(application),
            inputs={
                "version": 1,
                "identifier": identifier,
                "state": state,
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
