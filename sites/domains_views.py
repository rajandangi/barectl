"""Site Settings: change a site's names and HTTPS setting (Phase B #442)."""

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

from .domains_change import SLUG
from .forms import SiteDomainsForm
from .names import valid_identifier


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
    snapshot = state.snapshot
    site = _site(state, identifier)
    names = tuple(site.server_names) if site is not None else ()
    https = bool(site.https) if site is not None else True
    allowed = (
        site is not None
        and snapshot is not None
        and snapshot.collected.standing is not None
        and snapshot.collected.standing.standing == Standing.TARGET_STACK
        and snapshot.collected.sites.outcome == ObservationOutcome.OBSERVED
        and site.outcome == ObservationOutcome.OBSERVED
        and site.state == SiteState.MANAGED
        and site.file == f"/etc/caddy/sites/{identifier}.caddy"
    )
    return {
        "site_domains": names,
        "site_https": https,
        "site_domains_form": SiteDomainsForm(initial={"names": "\n".join(names), "https": https}),
        "site_domains_can_prepare": (
            allowed
            and state.can_prepare_changes
            and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
            and not services.read_changes(server).polling
        ),
    }


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_domains(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server, identifier, request.user)
    form = SiteDomainsForm(request.POST)
    if not context["site_domains_can_prepare"] or not form.is_valid():
        messages.error(
            request,
            "Choose the site's names from a current, complete site observation. "
            "Run discovery and resolve the server's findings first.",
        )
        return redirect("site_settings", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            SLUG,
            inputs={
                "version": 1,
                "identifier": identifier,
                "names": list(form.cleaned_data["names"]),
                "https": bool(form.cleaned_data["https"]),
            },
        )
    except OperationRefused:
        messages.error(request, "The saved connection changed. Refresh and prepare a new review.")
        return redirect("site_settings", pk=pk, identifier=identifier)
    except ValueError:
        messages.error(
            request,
            "This names-and-HTTPS request is unavailable. Refresh the page and try again.",
        )
        return redirect("site_settings", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_settings", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
