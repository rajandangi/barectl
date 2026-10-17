"""Prepare the Laravel Deploy and Roll back reviews from the site's Deployments section."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from bootstrap.standing import Standing
from discovery.models import ObservationOutcome, SiteState
from discovery.presentation import VIEW_SITES
from discovery.snapshot import ObservedSite
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server

from .deploy_forms import RollbackForm
from .names import valid_identifier

DEPLOY_SLUG = "deploy_laravel_site"
ROLLBACK_SLUG = "rollback_laravel_site"


def _site(state: DiscoveryState, identifier: str) -> ObservedSite | None:
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier), None
    )


def release_names(server: Server, identifier: str) -> tuple[str, ...]:
    """The site's retained releases that a Roll back may reactivate."""
    state = server_state(server)
    snapshot = state.snapshot
    if snapshot is None:
        return ()
    return tuple(
        release.name
        for release in snapshot.collected.releases.value
        if release.identifier == identifier
        and release.state == SiteState.MANAGED
        and not release.current
    )


def deploy_context(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    site = _site(state, identifier)
    naming = f"/etc/caddy/sites/{identifier}.caddy"
    ready = (
        snapshot is not None
        and site is not None
        and getattr(site, "file", "") == naming
        and site.state == SiteState.MANAGED
        and snapshot.collected.standing is not None
        and snapshot.collected.standing.standing == Standing.TARGET_STACK
        and snapshot.collected.releases.outcome == ObservationOutcome.OBSERVED
    )
    releases = snapshot.collected.releases.value if snapshot is not None else ()
    present = tuple(
        release for release in releases if release.identifier == identifier and release.current
    )
    choices = release_names(server, identifier)
    allowed = (
        ready
        and bool(present)
        and state.can_prepare_changes
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
        and not services.read_changes(server).polling
    )
    return {
        "deploy_ready": bool(ready and present),
        "deploy_can_prepare": bool(allowed),
        "rollback_can_prepare": bool(allowed and choices),
        "rollback_form": RollbackForm(choices=choices),
    }


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_deploy(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = deploy_context(server, identifier, request.user)
    if not context["deploy_can_prepare"]:
        messages.error(
            request,
            "Deploy needs a current Laravel release and a fresh site observation.",
        )
        return redirect("site_deployments", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server, request.user, DEPLOY_SLUG, inputs={"version": 1, "identifier": identifier}
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare a new review.")
        return redirect("site_deployments", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_deployments", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_rollback(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = deploy_context(server, identifier, request.user)
    form = RollbackForm(request.POST, choices=release_names(server, identifier))
    if not context["rollback_can_prepare"] or not form.is_valid():
        messages.error(request, "Choose a retained release from a fresh site observation.")
        return redirect("site_deployments", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            ROLLBACK_SLUG,
            inputs={
                "version": 1,
                "identifier": identifier,
                "release": form.cleaned_data["release"],
            },
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare a new review.")
        return redirect("site_deployments", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_deployments", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
