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
from .firewall import ACTIONS as FIREWALL_ACTIONS
from .firewall import PROTOCOLS as FIREWALL_PROTOCOLS
from .firewall import SLUG as FIREWALL_SLUG
from .sign_in import SLUG as SIGN_IN_SLUG
from .updates import CHECK_SLUG, INSTALL_SLUG, SELECTIONS


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, CHANGE_SHARED), raise_exception=True)
def prepare_firewall(request: HttpRequest, pk: int) -> HttpResponse:
    """Turn on the standard firewall, or add or remove one operator port."""
    selection = request.POST.get("selection", "")
    if selection not in FIREWALL_ACTIONS:
        return _redirect_problem(
            request, pk, "Choose whether to turn on the firewall or change one port."
        )
    inputs: dict[str, object] = {"version": 1, "selection": selection}
    if selection != "on":
        port = request.POST.get("port", "").strip()
        protocol = request.POST.get("protocol", "").strip().lower()
        network = request.POST.get("network", "").strip()
        if not port or protocol not in FIREWALL_PROTOCOLS:
            return _redirect_problem(request, pk, "Enter one port and choose TCP or UDP.")
        inputs.update(port=port, protocol=protocol)
        if network:
            inputs["network"] = network
    return _prepare(
        request,
        pk,
        FIREWALL_SLUG,
        inputs,
        "This server has no current manageable observation. Run a connection check and "
        "resolve any findings before changing the firewall.",
    )


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, CHANGE_SHARED), raise_exception=True)
def prepare_sign_in(request: HttpRequest, pk: int) -> HttpResponse:
    """Prepare the fixed key-only sign-in policy."""
    if request.POST.get("selection") != "on":
        return _redirect_problem(request, pk, "Choose Require key sign-in to continue.")
    return _prepare(
        request,
        pk,
        SIGN_IN_SLUG,
        {"version": 1, "selection": "on"},
        "Run a connection check and resolve the server's findings before changing sign-in.",
    )


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, CHANGE_SHARED), raise_exception=True)
def prepare_auto_updates(request: HttpRequest, pk: int) -> HttpResponse:
    """Turn Ubuntu's automatic security updates on or off through the change engine."""
    state = request.POST.get("state", "")
    if state not in STATES:
        return _redirect_problem(request, pk, "Choose whether to turn automatic updates on or off.")
    return _prepare(
        request,
        pk,
        SLUG,
        {"version": 1, "selection": state},
        "This server has no current manageable observation. Run a connection check and "
        "resolve any findings before changing automatic updates.",
    )


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, CHANGE_SHARED), raise_exception=True)
def prepare_updates_check(request: HttpRequest, pk: int) -> HttpResponse:
    """Refresh Ubuntu's package lists as its own reviewed change."""
    return _prepare(
        request,
        pk,
        CHECK_SLUG,
        {"version": 1},
        "This server has no current manageable observation. Run a connection check and "
        "resolve any findings before checking for Ubuntu updates.",
    )


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, CHANGE_SHARED), raise_exception=True)
def prepare_updates_install(request: HttpRequest, pk: int) -> HttpResponse:
    """Install the reviewed security updates only, or all waiting Ubuntu updates."""
    selection = request.POST.get("selection", "")
    if selection not in SELECTIONS:
        return _redirect_problem(
            request, pk, "Choose whether to install security updates only or all updates."
        )
    return _prepare(
        request,
        pk,
        INSTALL_SLUG,
        {"version": 1, "selection": selection},
        "This server has no current manageable observation. Run a connection check and "
        "resolve any findings before installing Ubuntu updates.",
    )


def _prepare(
    request: HttpRequest,
    pk: int,
    slug: str,
    inputs: dict[str, object],
    unmanageable: str,
) -> HttpResponse:
    if not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    if not server_state(server).can_prepare_changes:
        messages.error(request, unmanageable)
        return redirect("server_security", pk=pk)
    try:
        queued = change_services.request_prepare(server, request.user, slug, inputs=inputs)
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


def _redirect_problem(request: HttpRequest, pk: int, message: str) -> HttpResponse:
    messages.error(request, message)
    return redirect("server_security", pk=pk)
