"""The site's readiness form queues a reviewed native Caddy change through the worker."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from bootstrap.standing import Standing
from discovery.models import SiteState
from discovery.presentation import VIEW_SITES
from discovery.snapshot import ObservedSite
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server

from .forms import SiteReadinessForm
from .names import valid_identifier
from .readiness_change import SLUG


def _site(state: DiscoveryState, identifier: str) -> ObservedSite | None:
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier),
        None,
    )


def context_for_site(
    server: Server,
    identifier: str,
    user: User | AnonymousUser,
    *,
    has_releases: bool = False,
) -> dict[str, object]:
    state = server_state(server)
    site = _site(state, identifier)
    allowed = (
        site is not None
        and not has_releases
        and state.snapshot is not None
        and state.snapshot.collected.standing is not None
        and state.snapshot.collected.standing.standing == Standing.TARGET_STACK
        and site.file.startswith("/etc/caddy/sites/")
        and site.state == SiteState.MANAGED
    )
    return {
        "site_readiness": site.readiness if site is not None else "/",
        "site_readiness_form": SiteReadinessForm(
            initial={"readiness": site.readiness if site is not None else "/"}
        ),
        "site_readiness_laravel": has_releases,
        "site_readiness_can_prepare": allowed
        and state.can_prepare_changes
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
        and not services.read_changes(server).polling,
    }


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_readiness(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    snapshot = server_state(server).snapshot
    has_releases = bool(
        snapshot is not None
        and any(release.identifier == identifier for release in snapshot.collected.releases.value)
    )
    context = context_for_site(server, identifier, request.user, has_releases=has_releases)
    form = SiteReadinessForm(request.POST)
    if not context["site_readiness_can_prepare"] or not form.is_valid():
        messages.error(
            request, "Choose a readiness path from a current, complete site observation."
        )
        return redirect("site_runtime", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            SLUG,
            inputs={
                "version": 1,
                "identifier": identifier,
                "readiness": form.cleaned_data["readiness"],
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
