"""The Object cache setting's one prepare action (docs/dashboard-workflows.md).

Installing Valkey is the cache kind's own reviewed change; this view only queues the
preparation and hands the operator to the shared review screen. It is Shared consent, so a
Site operator is refused here as well as on the apply POST.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from operations.consent import PREPARE_PERMISSIONS
from operations.models import CHANGE_SHARED
from operations.services import request_prepare
from servers.discovery_state import server_state
from servers.models import Server

from . import engine


@never_cache
@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, CHANGE_SHARED), raise_exception=True)
def object_cache_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    if not isinstance(request.user, User):
        raise Http404
    if request.POST.get("kind", engine.SLUG) != engine.SLUG:
        messages.error(request, "Choose a supported object cache change.")
        return redirect("server_settings", pk=pk)
    if not server_state(server).can_prepare_changes:
        messages.error(
            request,
            "This server has no current manageable host-standing observation. Run discovery "
            "and resolve any Not manageable findings before preparing changes.",
        )
        return redirect("server_settings", pk=pk)
    try:
        queued = request_prepare(
            server,
            request.user,
            engine.SLUG,
            inputs={"version": 1},
        )
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(request, "Barectl refused invalid preparation inputs.")
        return redirect("server_settings", pk=pk)
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another remote operation for this server. Prepare the "
            "object cache change after it finishes.",
        )
        return redirect("server_settings", pk=pk)
    messages.success(
        request,
        f"Barectl queued a review of Install Valkey for {server.name}. Nothing changes until "
        "its review is applied.",
    )
    return redirect("change_detail", operation_id=queued.pk)
