"""A WordPress site's settings section (Phase B #383).

Opening the section makes no SSH connection: it lists the extra constant names the latest
observation recorded. Preparing a change queues a review; the new values are typed on the
review's confirm screen and reach the server only over ADR 0032's confidential channel.
"""

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
from operations.models import MANAGE_SECRETS
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from sites.names import valid_identifier
from sites.settings_forms import SettingsChangeForm

from . import convention
from .settings import SLUG

CHANGED = "The saved connection changed. Refresh and prepare a new review."
BUSY = "Wait for the current operation before preparing this review."


def _site(state: DiscoveryState, identifier: str) -> ObservedSite | None:
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier),
        None,
    )


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    site = _site(state, identifier)
    snapshot = state.snapshot
    standing = snapshot.collected.standing if snapshot is not None else None
    complete = (
        site is not None
        and site.application == "wordpress"
        and not site.application_problem
        and site.state == SiteState.MANAGED
        and site.file.startswith("/etc/caddy/sites/")
        and standing is not None
        and standing.standing == Standing.TARGET_STACK
    )
    settings = snapshot.collected.settings if snapshot is not None else None
    rows = (
        [
            {"key": item.key}
            for item in settings.value
            if item.identifier == identifier and item.application == "wordpress"
        ]
        if settings is not None and settings.observed
        else []
    )
    rows.sort(key=lambda row: str(row["key"]))
    allowed = (
        complete
        and state.can_prepare_changes
        and not services.read_changes(server).polling
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES, MANAGE_SECRETS))
    )
    return {
        "wordpress_settings_rows": rows,
        "wordpress_settings_observed": settings is not None and settings.observed,
        "wordpress_settings_form": SettingsChangeForm(),
        "wordpress_settings_can_prepare": allowed,
        "wordpress_settings_reserved": sorted(convention.RESERVED_CONSTANTS),
        "wordpress_settings_problem": settings.warning if settings is not None else "",
    }


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES, MANAGE_SECRETS), raise_exception=True)
def prepare_settings(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server, identifier, request.user)
    form = SettingsChangeForm(request.POST)
    if not context["wordpress_settings_can_prepare"] or not form.is_valid():
        messages.error(
            request,
            "Choose a key and whether to set or remove it on a current complete WordPress site.",
        )
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    if convention.reserved_constant(str(form.cleaned_data["key"])):
        messages.error(request, "That name is owned by Barectl and cannot be edited.")
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            SLUG,
            inputs={
                "version": 1,
                "identifier": identifier,
                "changes": [
                    {"key": form.cleaned_data["key"], "action": form.cleaned_data["action"]}
                ],
            },
        )
    except OperationRefused, ValueError:
        messages.error(request, CHANGED)
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, BUSY)
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
