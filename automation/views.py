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

from discovery.presentation import VIEW_SITES
from operations import change_requirements, preparation, services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import server_state
from servers.models import Server
from sites.names import valid_identifier
from sites.preparation import decide_for_site, site_facts

from . import change, presentation, scheduler
from .forms import SCHEDULER_STATES, STATES, ScheduleForm

CHANGED = "The saved connection changed. Refresh and prepare a new review."
BUSY = "Wait for the current operation before preparing this review."
INVALID = "Choose an action on a current, complete site with no other change in progress."


def _kind(application: str) -> str:
    return scheduler.SLUG if application == "laravel" else change.SLUG


def _choices(application: str) -> tuple[tuple[str, str], ...]:
    return SCHEDULER_STATES if application == "laravel" else STATES


def _application(facts: preparation.SiteFacts) -> str:
    """The one Laravel identity: a settings row or a release row, never ``site.application``."""
    if facts.laravel and not facts.wordpress:
        return "laravel"
    return "wordpress" if facts.wordpress else ""


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    facts = site_facts(state.snapshot, identifier)
    application = _application(facts)
    lines = (
        presentation.lines(
            state.snapshot.collected,
            identifier,
            state.snapshot.collected_at,
            presentation.paused_change(server, identifier),
        )
        if state.snapshot is not None and application
        else ()
    )
    line = lines[0] if lines else None
    requirements = (
        change_requirements.LARAVEL_TASKS
        if application == "laravel"
        else change_requirements.WORDPRESS_TASKS
    )
    decision = decide_for_site(state, user, identifier, requirements)
    allowed = decision.allowed
    return {
        "scheduled_tasks": line,
        "scheduled_tasks_kind": application,
        "scheduled_tasks_can_prepare": allowed,
        "scheduled_tasks_can_stop": allowed,
        "scheduled_tasks_can_run": allowed and bool(line and line.on and not line.running),
        "scheduled_tasks_form": ScheduleForm(choices=_choices(application)),
        "scheduled_tasks_reason": decision.sentence,
        "scheduled_tasks_ready": allowed,
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
    if not context["scheduled_tasks_can_prepare"]:
        messages.error(request, str(context["scheduled_tasks_reason"]))
        return redirect("site_settings", pk=pk, identifier=identifier)
    form = ScheduleForm(request.POST, choices=_choices(application))
    if not form.is_valid():
        messages.error(request, INVALID)
        return redirect("site_settings", pk=pk, identifier=identifier)
    state = form.cleaned_data["state"]
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
