"""Prepare the Laravel Deploy and Roll back reviews from the site's Deployments section."""

from dataclasses import replace

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from discovery.models import SiteState
from discovery.presentation import VIEW_SITES
from operations import preparation, services
from operations.consent import PREPARE_PERMISSIONS
from operations.inputs import PreparationInputs
from operations.lifecycle import OperationRefused
from servers.discovery_state import server_state
from servers.models import Server
from sites.preparation import decide_for_site

from .deploy_forms import DeploySettingsForm, RollbackForm
from .models import SiteDeploySetting
from .names import valid_identifier

DEPLOY_SLUG = "deploy_laravel_site"
ROLLBACK_SLUG = "rollback_laravel_site"

CHANGED = "The saved connection changed. Refresh and prepare a new review."
BUSY = "Wait for the current operation before preparing this review."
INVALID = "Choose a retained release from a fresh site observation."


def deploy_settings(server: Server, identifier: str) -> SiteDeploySetting:
    """This controller's saved Deploy switches for the site, defaulting to on."""
    setting = SiteDeploySetting.objects.filter(server=server, identifier=identifier).first()
    if setting is None:
        return SiteDeploySetting(server=server, identifier=identifier, run_migrations=True)
    return setting


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


def _deploy_requirements() -> preparation.Requirements:
    return replace(
        preparation.SITE,
        application="laravel",
        releases_observed=True,
        current_release=True,
        open_site=True,
    )


def _rollback_requirements() -> preparation.Requirements:
    return replace(
        preparation.SITE,
        application="laravel",
        releases_observed=True,
        retained_release=True,
        open_site=True,
    )


def deploy_context(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    deploy = decide_for_site(state, user, identifier, _deploy_requirements())
    rollback = decide_for_site(state, user, identifier, _rollback_requirements())
    releases = snapshot.collected.releases.value if snapshot is not None else ()
    present = tuple(
        release for release in releases if release.identifier == identifier and release.current
    )
    choices = release_names(server, identifier)
    setting = deploy_settings(server, identifier)
    polling = services.read_changes(server).polling
    permitted = user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
    return {
        "deploy_can_prepare": deploy.allowed,
        "deploy_reason": deploy.reason.sentence if deploy.reason else "",
        "deploy_settings_can_save": bool(permitted and not polling and present),
        "rollback_can_prepare": rollback.allowed,
        "rollback_reason": rollback.reason.sentence if rollback.reason else "",
        "rollback_form": RollbackForm(choices=choices),
        "deploy_settings_form": DeploySettingsForm(run_migrations=setting.run_migrations),
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
        messages.error(request, str(context["deploy_reason"]))
        return redirect("site_deployments", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            DEPLOY_SLUG,
            inputs=PreparationInputs(
                "", identifier, migrations=deploy_settings(server, identifier).run_migrations
            ).document(),
        )
    except OperationRefused, ValueError:
        messages.error(request, CHANGED)
        return redirect("site_deployments", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, BUSY)
        return redirect("site_deployments", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def save_deploy_settings(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Save this controller's Deploy switches for the site."""
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    form = DeploySettingsForm(request.POST)
    if not form.is_valid():
        messages.error(request, "The Deploy settings could not be read. Try again.")
        return redirect("site_deployments", pk=pk, identifier=identifier)
    SiteDeploySetting.objects.update_or_create(
        server=server,
        identifier=identifier,
        defaults={"run_migrations": bool(form.cleaned_data["run_migrations"])},
    )
    messages.success(request, "Deploy settings saved for this site.")
    return redirect("site_deployments", pk=pk, identifier=identifier)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_rollback(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = deploy_context(server, identifier, request.user)
    if not context["rollback_can_prepare"]:
        messages.error(request, str(context["rollback_reason"]))
        return redirect("site_deployments", pk=pk, identifier=identifier)
    form = RollbackForm(request.POST, choices=release_names(server, identifier))
    if not form.is_valid():
        messages.error(request, INVALID)
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
        messages.error(request, CHANGED)
        return redirect("site_deployments", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, BUSY)
        return redirect("site_deployments", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
