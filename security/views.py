"""Explicit Security change requests (Phase E #303, #179).

Opening Security reads the stored snapshot only. Preparing a change is this POST, which
queues the reviewed preparation and never connects to the server itself.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from operations import services as change_services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from operations.models import CHANGE_SHARED
from servers.discovery_state import server_state
from servers.models import Server

from .change import SLUG, STATES


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, CHANGE_SHARED), raise_exception=True)
def prepare_auto_updates(request: HttpRequest, pk: int) -> HttpResponse:
    """Turn Ubuntu's automatic security updates on or off through the change engine."""
    if not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    if not server_state(server).can_prepare_changes:
        messages.error(
            request,
            "This server has no current manageable observation. Run a connection check and "
            "resolve any findings before changing automatic updates.",
        )
        return redirect("server_security", pk=pk)
    state = request.POST.get("state", "")
    if state not in STATES:
        messages.error(request, "Choose whether to turn automatic updates on or off.")
        return redirect("server_security", pk=pk)
    try:
        queued = change_services.request_prepare(
            server,
            request.user,
            SLUG,
            inputs={"version": 1, "selection": state},
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and try again.")
        return redirect("server_security", pk=pk)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another operation for this server. Try again after it finishes.",
        )
        return redirect("server_security", pk=pk)
    return redirect("change_detail", operation_id=queued.pk)
