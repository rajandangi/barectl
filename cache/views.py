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

from discovery.presentation import VIEW_SITES
from operations.consent import PREPARE_PERMISSIONS
from operations.inputs import INVALID_INPUTS
from operations.lifecycle import OperationBusy, OperationRefused
from operations.models import CHANGE_SHARED
from operations.services import request_prepare
from servers.discovery_state import server_state
from servers.models import Server

from . import engine
from .forms import ObjectCacheForm
from .instance import SLUG as SET_SITE_OBJECT_CACHE_SLUG
from .presentation import site_context
from .reading import READ_PERMISSIONS, request_reading

BUSY = "Wait for the current operation before preparing this change."


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


@never_cache
@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_site_cache(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Turn one site's own object cache on or off, or load its PHP client first."""
    from sites.names import valid_identifier

    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = site_context(server, identifier, request.user)
    if not context["object_cache_applicable"]:
        messages.error(request, "This site is not a verified WordPress installation.")
        return redirect("site_settings", pk=pk, identifier=identifier)
    form = ObjectCacheForm(
        request.POST,
        choices=tuple(context["object_cache_memory_choices"]),  # type: ignore[arg-type]
        selected=int(str(context["object_cache_memory_mib"])),
    )
    if not form.is_valid():
        messages.error(request, "Choose a supported object cache action.")
        return redirect("site_settings", pk=pk, identifier=identifier)
    action = str(form.cleaned_data["action"])
    if action == "client":
        slug = "set_site_php_client"
        inputs: dict[str, object] = {
            "version": 1,
            "identifier": identifier,
            "php_client": True,
        }
    else:
        if not context["object_cache_can_prepare"]:
            messages.error(
                request,
                "This site is not ready for an object cache change. Run discovery, resolve "
                "the server's findings, or wait for the current change.",
            )
            return redirect("site_settings", pk=pk, identifier=identifier)
        slug = SET_SITE_OBJECT_CACHE_SLUG
        memory = int(str(form.cleaned_data["memory"])) if action == "on" else 0
        inputs = {
            "version": 1,
            "identifier": identifier,
            "object_cache": action == "on",
            "maxmemory_mib": memory,
        }
    try:
        queued = request_prepare(server, request.user, slug, inputs=inputs)
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(request, INVALID_INPUTS)
        return redirect("site_settings", pk=pk, identifier=identifier)
    except OperationRefused, OperationBusy:
        messages.error(request, BUSY)
        return redirect("site_settings", pk=pk, identifier=identifier)
    if queued is None:
        messages.warning(request, BUSY)
        return redirect("site_settings", pk=pk, identifier=identifier)
    messages.success(
        request,
        f"Barectl queued the object cache change for {identifier}. Nothing changes until its "
        "review is applied.",
    )
    return redirect("change_detail", operation_id=queued.pk)


@never_cache
@require_POST
@login_required
@permission_required(READ_PERMISSIONS, raise_exception=True)
def read_site_cache(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Queue one on-demand reading of the site's cache metrics."""
    from sites.names import valid_identifier

    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    try:
        queued = request_reading(server, request.user, identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError, OperationRefused:
        messages.error(request, "Barectl could not read this site's cache.")
        return redirect("site_settings", pk=pk, identifier=identifier)
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another remote operation for this server. Check the cache "
            "after it finishes.",
        )
        return redirect("site_settings", pk=pk, identifier=identifier)
    messages.success(request, "Barectl is reading this site's cache.")
    return redirect("site_settings", pk=pk, identifier=identifier)
