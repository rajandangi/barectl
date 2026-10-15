from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from bootstrap.standing import Standing
from discovery.models import SiteState
from discovery.presentation import VIEW_SITES
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server

from .names import valid_identifier
from .php_change import CHOICES, SLUG
from .php_forms import SitePhpForm


def choices_for(state: DiscoveryState) -> tuple[str, ...]:
    snapshot = state.snapshot
    if snapshot is None or state.snapshot_notice is not None:
        return ()
    return tuple(
        row.entry for row in snapshot.collected.runtimes if row.entry in CHOICES and row.manageable
    )


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    site = (
        next(
            (site for site in snapshot.collected.sites.value if site.identifier == identifier), None
        )
        if snapshot
        else None
    )
    choices = choices_for(state)
    allowed = (
        site is not None
        and snapshot is not None
        and snapshot.collected.standing is not None
        and snapshot.collected.standing.standing == Standing.TARGET_STACK
        and site.file.startswith("/etc/caddy/sites/")
        and site.state == SiteState.MANAGED
    )
    return {
        "php_runtime_selection": site.php_version if site else "",
        "php_runtime_form": SitePhpForm(choices=choices, selected=site.php_version if site else ""),
        "php_can_prepare": bool(choices)
        and allowed
        and state.can_prepare_changes
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
        and not services.read_changes(server).polling,
    }


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_php(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server, identifier, request.user)
    form = SitePhpForm(request.POST, choices=choices_for(server_state(server)))
    if not context["php_can_prepare"] or not form.is_valid():
        messages.error(request, "Choose an installed PHP runtime from a fresh site observation.")
        return redirect("site_runtime", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            SLUG,
            inputs={
                "version": 1,
                "identifier": identifier,
                "selection": form.cleaned_data["selection"],
            },
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare a new review.")
        return redirect("site_runtime", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_runtime", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
