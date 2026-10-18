"""The per-site Database setting: its panel and its one prepare action.

docs/dashboard-workflows.md and #179's Site Settings journey. A plain PHP site adds its own
database here; the panel shows the convention's connection details from the server's last
observation alone, and the review reads the engine catalog natively.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from bootstrap.standing import Standing
from discovery.models import ObservationOutcome, SiteState
from discovery.presentation import VIEW_SITES
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import server_state
from servers.models import Server
from sites.names import valid_identifier

from . import presentation
from . import site as site_kind

SLUG = site_kind.SLUG


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    site = (
        next(
            (site for site in snapshot.collected.sites.value if site.identifier == identifier),
            None,
        )
        if snapshot
        else None
    )
    allowed = (
        site is not None
        and snapshot is not None
        and snapshot.collected.standing is not None
        and snapshot.collected.standing.standing == Standing.TARGET_STACK
        and snapshot.collected.sites.outcome == ObservationOutcome.OBSERVED
        and site.outcome == ObservationOutcome.OBSERVED
        and site.file == f"/etc/caddy/sites/{identifier}.caddy"
        and site.state == SiteState.MANAGED
    )
    return {
        "site_database_panel": (
            presentation.site_panel(snapshot.collected, identifier)
            if snapshot is not None
            else None
        ),
        "site_database_can_prepare": (
            allowed
            and state.can_prepare_changes
            and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
            and not services.read_changes(server).polling
        ),
    }


@never_cache
@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_site_database(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server, identifier, request.user)
    if not context["site_database_can_prepare"]:
        messages.error(
            request,
            "Run discovery, resolve the server's findings and install one database engine "
            "before adding this site's database.",
        )
        return redirect("site_database", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            SLUG,
            inputs={"version": 1, "identifier": identifier},
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare a new review.")
        return redirect("site_database", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_database", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
