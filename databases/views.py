"""The Database setting's one prepare action (docs/dashboard-workflows.md).

Installing and removing a database engine are the engine's own reviewed changes; this view
only queues the preparation and hands the operator to the shared review screen.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from operations.consent import PREPARE_PERMISSIONS
from operations.services import request_prepare
from servers.discovery_state import server_state
from servers.models import Server

from . import engine


@never_cache
@require_POST
@login_required
@permission_required(PREPARE_PERMISSIONS, raise_exception=True)
def database_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    if not isinstance(request.user, User):
        raise Http404
    kind_slug = request.POST.get("kind", engine.SLUG)
    if kind_slug not in {engine.SLUG, engine.REMOVE_SLUG}:
        messages.error(request, "Choose a supported database change.")
        return redirect("server_settings", pk=pk)
    selection = request.POST.get("selection", "")
    if selection not in engine.ENGINE_CHOICES:
        messages.error(request, "Choose MariaDB or PostgreSQL.")
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
            kind_slug,
            inputs={"version": 1, "selection": selection},
        )
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(request, "Choose MariaDB or PostgreSQL.")
        return redirect("server_settings", pk=pk)
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another remote operation for this server. Prepare the "
            "database change after it finishes.",
        )
        return redirect("server_settings", pk=pk)
    label = engine.LABEL if kind_slug == engine.SLUG else engine.REMOVE_LABEL
    messages.success(
        request,
        f"Barectl queued a review of {label} for {server.name}. Nothing changes until its "
        "review is applied.",
    )
    return redirect("change_detail", operation_id=queued.pk)
