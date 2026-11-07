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

from discovery.presentation import VIEW_SITES
from operations import preparation, services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import server_state
from servers.models import Server
from sites.names import valid_identifier
from sites.preparation import decide_for_site

from . import presentation
from . import site as site_kind

SLUG = site_kind.SLUG


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    decision = decide_for_site(state, user, identifier, preparation.SITE)
    return {
        "site_database_panel": (
            presentation.site_panel(snapshot.collected, identifier)
            if snapshot is not None
            else None
        ),
        "site_database_can_prepare": decision.allowed,
        "site_database_reason": decision.reason.sentence if decision.reason else "",
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
            str(context["site_database_reason"])
            or (
                "Run discovery, resolve the server's findings and install one database engine "
                "before adding this site's database."
            ),
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
