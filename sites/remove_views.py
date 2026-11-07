"""Site Settings: the one destructive action a site carries (Phase B #385)."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from backups import presentation as backup_presentation
from discovery.presentation import VIEW_SITES
from operations import change_requirements, services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from sites.names import canonical_name, valid_identifier

from . import remove as remove_kind
from .preparation import decide_for_site

SLUG = remove_kind.SLUG


def context_for_site(
    state: DiscoveryState, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    snapshot = state.snapshot
    site = state.site(identifier)
    names = tuple(site.domains) if site is not None else ()
    backup = (
        backup_presentation.backup_of(snapshot.collected, identifier)
        if snapshot is not None
        else None
    )
    decision = decide_for_site(
        state,
        user,
        identifier,
        change_requirements.SITE_REMOVE,
    )
    return {
        "site_remove_has_backups": backup is not None and backup.enabled,
        "site_remove_domains": names,
        "site_remove_primary": names[0] if names else "",
        "site_remove_can_prepare": decision.allowed,
        "site_remove_reason": decision.sentence,
    }


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_remove(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server_state(server), identifier, request.user)
    if not context["site_remove_can_prepare"]:
        messages.error(
            request,
            str(context["site_remove_reason"])
            or (
                "Run discovery, resolve the server's findings and wait for any current operation "
                "before preparing this site's removal."
            ),
        )
        return redirect("site_settings", pk=pk, identifier=identifier)
    primary = str(context["site_remove_primary"])
    if not primary:
        submitted = request.POST.get("primary", "").strip()
        canonical, problem = canonical_name(submitted)
        if problem:
            messages.error(
                request,
                "Type the site's primary domain to prepare its removal review.",
            )
            return redirect("site_settings", pk=pk, identifier=identifier)
        primary = canonical
    inputs: dict[str, object] = {
        "version": 1,
        "identifier": identifier,
        "primary": primary,
    }
    try:
        queued = services.request_prepare(server, request.user, SLUG, inputs=inputs)
    except OperationRefused:
        messages.error(request, "The saved connection changed. Refresh and prepare a new review.")
        return redirect("site_settings", pk=pk, identifier=identifier)
    except ValueError:
        messages.error(
            request,
            "Barectl could not prepare this removal from the request. Refresh the page and "
            "try again.",
        )
        return redirect("site_settings", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_settings", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
