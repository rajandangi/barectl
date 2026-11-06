"""A Laravel site's **Settings > Queue workers** section (Phase C #266).

Opening the section makes no SSH connection: it renders the latest observation's projection
and the definition read from the site's own units. Preparing a change queues one Site
review; the confirm screen and run progress are the shared change screens.
"""

from dataclasses import replace

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from discovery.presentation import VIEW_SITES
from operations import preparation, services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import server_state
from servers.models import Server
from sites.names import valid_identifier
from sites.preparation import decide_for_site, site_facts

from . import worker_presentation, workers
from .worker_change import SLUG
from .worker_forms import WorkerForm

CHANGED = "The saved connection changed. Refresh and prepare a new review."
BUSY = "Wait for the current operation before preparing this review."
INVALID = "Choose an action on a current Laravel site with no other change in progress."


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    facts = site_facts(snapshot, identifier)
    laravel = facts.laravel
    row = (
        worker_presentation.row_for(snapshot.collected, identifier)
        if snapshot and laravel
        else None
    )
    view = worker_presentation.worker_view(
        identifier, row, snapshot.collected_at if snapshot else None
    )
    decision = decide_for_site(
        state,
        user,
        identifier,
        replace(
            preparation.SITE,
            state=None,
            application="laravel",
            current_release=True,
            open_site=True,
        ),
    )
    allowed = decision.allowed
    definition = row.definition if row is not None else None
    installed = bool(row and row.installed)
    enabled = bool(row and row.enabled)
    return {
        "queue_workers": view if laravel else None,
        "queue_workers_can_prepare": allowed,
        "queue_workers_can_start": allowed,
        "queue_workers_can_stop": allowed
        and installed
        and (enabled or bool(row and row.active_processes)),
        "queue_workers_can_restart": allowed and installed and enabled and definition is not None,
        "queue_workers_problem": row.problem if row is not None else "",
        "queue_workers_form": WorkerForm(definition=definition),
        "queue_workers_definition": definition,
        "queue_workers_reason": decision.reason.sentence if decision.reason else "",
        "queue_workers_ready": allowed,
    }


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_workers(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server, identifier, request.user)
    if not context["queue_workers_can_prepare"]:
        messages.error(request, str(context["queue_workers_reason"]))
        return redirect("site_settings", pk=pk, identifier=identifier)
    definition = context["queue_workers_definition"]
    form = WorkerForm(
        request.POST,
        definition=definition if isinstance(definition, workers.WorkerDefinition) else None,
    )
    if not form.is_valid():
        messages.error(request, INVALID)
        return redirect("site_settings", pk=pk, identifier=identifier)
    action = str(form.cleaned_data["action"])
    inputs: dict[str, object] = {
        "version": 1,
        "identifier": identifier,
        "action": action,
    }
    if action == "start":
        parsed = form.definition
        if parsed is None:
            messages.error(
                request, "Type the queue names, the number of processes and the job timeout."
            )
            return redirect("site_settings", pk=pk, identifier=identifier)
        inputs.update(
            queues=list(parsed.queues),
            processes=parsed.processes,
            timeout=parsed.timeout,
        )
    try:
        queued = services.request_prepare(server, request.user, SLUG, inputs=inputs)
    except OperationRefused, ValueError:
        messages.error(request, CHANGED)
        return redirect("site_settings", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, BUSY)
        return redirect("site_settings", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
