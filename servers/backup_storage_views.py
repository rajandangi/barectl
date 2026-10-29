"""The two Server Settings > Backup storage prepare actions (Phase D #403).

The views validate the operator's non-secret answers and queue one reviewed change; no SSH
connection happens here, and the keys reach the worker only through the confirmation screen.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from discovery.presentation import VIEW_SITES
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from operations.models import MANAGE_SECRETS
from servers.discovery_state import server_state
from servers.models import Server

from .backup_storage import CONNECT_KIND, REMOVE_KIND, REPLACE_KIND, SETUP_KIND

PERMISSIONS = (*PREPARE_PERMISSIONS, VIEW_SITES, MANAGE_SECRETS)


@never_cache
@require_POST
@login_required
@permission_required(PERMISSIONS, raise_exception=True)
def prepare_storage(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    if not isinstance(request.user, User):
        raise Http404
    provider = request.POST.get("provider", "")
    inputs: dict[str, object] = {
        "version": 1,
        "provider": provider,
        "bucket": request.POST.get("bucket", ""),
    }
    if provider == "s3":
        inputs["region"] = request.POST.get("region", "")
    elif provider == "r2":
        inputs["account"] = request.POST.get("account", "")
    else:
        messages.error(request, "Choose Amazon S3 or Cloudflare R2.")
        return redirect("server_settings", pk=pk)
    if not server_state(server).can_prepare_changes:
        messages.error(
            request,
            "This server has no current manageable host-standing observation. Run discovery "
            "and resolve any Not manageable findings before changing backup storage.",
        )
        return redirect("server_settings", pk=pk)
    try:
        queued = services.request_prepare(server, request.user, SETUP_KIND, inputs=inputs)
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(request, "Check the bucket, region or account and try again.")
        return redirect("server_settings", pk=pk)
    except OperationRefused:
        messages.error(request, "Barectl could not prepare this change. Refresh and try again.")
        return redirect("server_settings", pk=pk)
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another operation for this server. Prepare the backup "
            "storage change after it finishes.",
        )
        return redirect("server_settings", pk=pk)
    messages.success(request, "Barectl is checking the server for a fresh confirmation.")
    return redirect("change_detail", operation_id=queued.pk)


@never_cache
@require_POST
@login_required
@permission_required(PERMISSIONS, raise_exception=True)
def prepare_remove_storage(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    if not isinstance(request.user, User):
        raise Http404
    if not server_state(server).can_prepare_changes:
        messages.error(
            request,
            "This server has no current manageable host-standing observation. Run discovery first.",
        )
        return redirect("server_settings", pk=pk)
    try:
        queued = services.request_prepare(server, request.user, REMOVE_KIND, inputs={"version": 1})
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(request, "Barectl could not prepare this change.")
        return redirect("server_settings", pk=pk)
    except OperationRefused:
        messages.error(request, "Barectl could not prepare this change. Refresh and try again.")
        return redirect("server_settings", pk=pk)
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another operation for this server. Prepare the removal after "
            "it finishes.",
        )
        return redirect("server_settings", pk=pk)
    messages.success(request, "Barectl is checking the server for a fresh confirmation.")
    return redirect("change_detail", operation_id=queued.pk)


@never_cache
@require_POST
@login_required
@permission_required(PERMISSIONS, raise_exception=True)
def prepare_connect(request: HttpRequest, pk: int) -> HttpResponse:
    """Open another server's offsite storage with the kit's facts and its secrets."""
    server = get_object_or_404(Server, pk=pk)
    if not isinstance(request.user, User):
        raise Http404
    provider = request.POST.get("provider", "")
    sites = tuple(
        dict.fromkeys(
            item for item in request.POST.get("sites", "").replace(",", " ").split() if item
        )
    )
    inputs: dict[str, object] = {
        "version": 1,
        "provider": provider,
        "bucket": request.POST.get("bucket", ""),
        "prefix": request.POST.get("prefix", ""),
        "sites": list(sites),
    }
    if provider == "s3":
        inputs["region"] = request.POST.get("region", "")
    elif provider == "r2":
        inputs["account"] = request.POST.get("account", "")
    else:
        messages.error(request, "Choose Amazon S3 or Cloudflare R2.")
        return redirect("server_settings", pk=pk)
    if not server_state(server).can_prepare_changes:
        messages.error(
            request,
            "This server has no current manageable host-standing observation. Run discovery "
            "and resolve any Not manageable findings before connecting backup storage.",
        )
        return redirect("server_settings", pk=pk)
    try:
        queued = services.request_prepare(server, request.user, CONNECT_KIND, inputs=inputs)
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(
            request,
            "Check the bucket, region or account, prefix and source sites from the recovery "
            "kit, then try again.",
        )
        return redirect("server_settings", pk=pk)
    except OperationRefused:
        messages.error(request, "Barectl could not prepare this change. Refresh and try again.")
        return redirect("server_settings", pk=pk)
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another operation for this server. Connect the backup "
            "storage after it finishes.",
        )
        return redirect("server_settings", pk=pk)
    messages.success(request, "Barectl is checking the server for a fresh confirmation.")
    return redirect("change_detail", operation_id=queued.pk)


@never_cache
@require_POST
@login_required
@permission_required(PERMISSIONS, raise_exception=True)
def prepare_replace_passphrase(request: HttpRequest, pk: int) -> HttpResponse:
    """Replace the recovery passphrase on every enabled site repository."""
    server = get_object_or_404(Server, pk=pk)
    if not isinstance(request.user, User):
        raise Http404
    if not server_state(server).can_prepare_changes:
        messages.error(
            request,
            "This server has no current manageable host-standing observation. Run discovery first.",
        )
        return redirect("server_settings", pk=pk)
    try:
        queued = services.request_prepare(server, request.user, REPLACE_KIND, inputs={"version": 1})
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(request, "Barectl could not prepare this change.")
        return redirect("server_settings", pk=pk)
    except OperationRefused:
        messages.error(request, "Barectl could not prepare this change. Refresh and try again.")
        return redirect("server_settings", pk=pk)
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another operation for this server. Replace the passphrase "
            "after it finishes.",
        )
        return redirect("server_settings", pk=pk)
    messages.success(request, "Barectl is checking the server for a fresh confirmation.")
    return redirect("change_detail", operation_id=queued.pk)
