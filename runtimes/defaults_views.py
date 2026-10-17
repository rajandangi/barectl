from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import AnonymousUser, User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from bootstrap.standing import Standing
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import server_state
from servers.models import Server

from .defaults import DefaultsObservation
from .defaults_forms import DefaultRuntimeForm


def context_for_server(server: Server, user: User | AnonymousUser) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    observation = snapshot.collected.runtime_defaults if snapshot is not None else None
    defaults = observation or DefaultsObservation()
    fresh = snapshot is not None and state.snapshot_notice is None
    standing = snapshot.collected.standing if snapshot is not None else None
    can_prepare = (
        fresh
        and state.can_prepare_changes
        and user.has_perms(PREPARE_PERMISSIONS)
        and standing is not None
        and standing.standing == Standing.TARGET_STACK
        and not services.read_changes(server).polling
    )
    return {
        "default_php_form": DefaultRuntimeForm(
            choices=defaults.php_choices if fresh else (), selected=defaults.php, family="php"
        ),
        "default_node_form": DefaultRuntimeForm(
            choices=defaults.node_choices if fresh else (), selected=defaults.node, family="node"
        ),
        "runtime_defaults": defaults,
        "default_php_can_prepare": can_prepare
        and bool(defaults.php_choices)
        and not defaults.php_problem,
        "default_node_can_prepare": can_prepare
        and bool(defaults.node_choices)
        and not defaults.node_problem,
    }


@require_POST
@login_required
def prepare_default(request: HttpRequest, pk: int, family: str) -> HttpResponse:
    if family not in ("php", "node"):
        raise Http404
    if (
        not isinstance(request.user, User)
        or not request.user.has_perm("servers.view_server")
        or not request.user.has_perms(PREPARE_PERMISSIONS)
    ):
        raise PermissionDenied
    server = get_object_or_404(Server, pk=pk)
    context = context_for_server(server, request.user)
    if not context["default_" + family + "_can_prepare"]:
        messages.error(
            request,
            "Run discovery and resolve the default command findings before preparing a change.",
        )
        return redirect("server_stack", pk=pk)
    observed = context["runtime_defaults"]
    if not isinstance(observed, DefaultsObservation):
        raise ValueError("Invalid recorded defaults.")
    form = DefaultRuntimeForm(
        request.POST,
        choices=observed.php_choices if family == "php" else observed.node_choices,
        family=family,
    )
    if not form.is_valid():
        messages.error(request, "Choose an installed runtime before preparing its default review.")
        return redirect("server_stack", pk=pk)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            "set_default_" + family,
            inputs={"version": 1, "selection": form.cleaned_data["selection"]},
        )
    except OperationRefused:
        messages.error(
            request, "The saved connection changed. Run discovery and prepare a new review."
        )
        return redirect("server_stack", pk=pk)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.warning(
            request, "Another remote operation is active. Prepare this review after it finishes."
        )
        return redirect("server_stack", pk=pk)
    return redirect("change_detail", operation_id=queued.pk)
