"""The site Backups section and its three actions (Phase D #396, #179)."""

from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from bootstrap.standing import Standing
from discovery.models import ObservationOutcome
from discovery.presentation import VIEW_SITES
from discovery.snapshot import Snapshot
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from operations.models import MANAGE_SECRETS
from servers.discovery_state import server_state
from servers.models import Server
from sites.bodies.common import SITE_GATED
from sites.names import valid_identifier

from . import check, presentation
from .change import BACKUP_SLUG, ENABLE_SLUG, FULL_SLUG
from .reopen import SLUG as REOPEN_SLUG

if TYPE_CHECKING:
    from discovery.snapshot import ObservedSite


def _site(server: Server, identifier: str) -> tuple[Snapshot | None, ObservedSite | None]:
    snapshot = server_state(server).snapshot
    if snapshot is None:
        return None, None
    site = next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier),
        None,
    )
    return snapshot, site


def _target(snapshot: Snapshot | None, site: ObservedSite | None) -> bool:
    return site is not None and site.file == f"/etc/caddy/sites/{site.identifier}.caddy"


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    """Everything the Backups section shows, from stored rows only; no SSH."""
    state = server_state(server)
    snapshot = state.snapshot
    site = (
        next(
            (site for site in snapshot.collected.sites.value if site.identifier == identifier),
            None,
        )
        if snapshot is not None
        else None
    )
    collected = snapshot.collected if snapshot is not None else None
    latest = check.latest_check(server, identifier)
    active = check.active(server, identifier)
    gated = site is not None and SITE_GATED in site.missing
    view = presentation.view(
        site, collected, identifier, latest, checking=active is not None, gated=gated
    )
    target = _target(snapshot, site)
    ready = (
        target
        and snapshot is not None
        and snapshot.collected.standing is not None
        and snapshot.collected.standing.standing == Standing.TARGET_STACK
        and site is not None
        and site.outcome == ObservationOutcome.OBSERVED
        and (site.state == "managed" or gated)
    )
    managed = ready and site is not None and site.state == "managed"
    polling = services.read_changes(server).polling
    can_prepare = bool(
        ready
        and state.can_prepare_changes
        and not polling
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
    )
    return {
        "backups": view,
        "backups_target": target,
        "backups_can_enable": can_prepare and managed and user.has_perm(MANAGE_SECRETS),
        "backups_can_back_up": can_prepare and managed and view.enabled and view.database,
        "backups_can_back_up_full": can_prepare and managed and view.enabled,
        "backups_can_reopen": can_prepare and view.reopen,
        "backups_can_check": bool(
            managed and user.has_perms((*check.READ_PERMISSIONS, VIEW_SITES))
        ),
        "backups_database_reason": ("" if view.database else view.database_reason),
        "backups_polling": polling or active is not None,
        "backups_kit_lines": presentation.kit_lines(server.name, identifier, collected),
    }


@never_cache
@require_GET
@login_required
@permission_required(("servers.view_server", VIEW_SITES), raise_exception=True)
def recovery_kit(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    snapshot, site = _site(server, identifier)
    if not _target(snapshot, site):
        raise Http404
    collected = snapshot.collected if snapshot is not None else None
    lines = presentation.kit_lines(server.name, identifier, collected)
    return render(
        request,
        "backups/recovery_kit.html",
        {"server": server, "identifier": identifier, "lines": lines},
    )


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES, MANAGE_SECRETS), raise_exception=True)
def prepare_enable(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    return _prepare(request, pk, identifier, ENABLE_SLUG, "site_backups")


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_backup(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    scope = request.POST.get("scope", "database")
    if scope == "full":
        return _prepare(request, pk, identifier, FULL_SLUG, "site_backups")
    if scope != "database":
        raise Http404
    return _prepare(request, pk, identifier, BACKUP_SLUG, "site_backups")


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_reopen(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    return _prepare(request, pk, identifier, REOPEN_SLUG, "site_backups")


def _prepare(
    request: HttpRequest, pk: int, identifier: str, slug: str, target: str
) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server, identifier, request.user)
    if slug == ENABLE_SLUG and not context["backups_can_enable"]:
        messages.error(
            request,
            "Barectl cannot enable backups here yet. Run discovery and resolve the "
            "server's findings, or wait for the current operation.",
        )
        return redirect(target, pk=pk, identifier=identifier)
    if slug == BACKUP_SLUG and not context["backups_can_back_up"]:
        messages.error(
            request,
            "Barectl cannot take this backup yet. Enable backups and add the site's "
            "database first, or wait for the current operation.",
        )
        return redirect(target, pk=pk, identifier=identifier)
    if slug == FULL_SLUG and not context["backups_can_back_up_full"]:
        messages.error(
            request,
            "Barectl cannot take a full backup yet. Enable backups and wait for the current "
            "operation.",
        )
        return redirect(target, pk=pk, identifier=identifier)
    if slug == REOPEN_SLUG and not context["backups_can_reopen"]:
        messages.error(
            request,
            "This site is not paused by a full backup, so there is nothing to reopen.",
        )
        return redirect(target, pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            slug,
            inputs={"version": 1, "identifier": identifier},
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare again.")
        return redirect(target, pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect(target, pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)


@require_POST
@login_required
@permission_required((*check.READ_PERMISSIONS, VIEW_SITES), raise_exception=True)
def check_now(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server, identifier, request.user)
    if not context["backups_can_check"]:
        messages.error(
            request,
            "Barectl cannot check this site's backups yet. Run discovery and resolve the "
            "server's findings first.",
        )
        return redirect("site_backups", pk=pk, identifier=identifier)
    try:
        queued = check.request_check(server, request.user, identifier)
    except OperationRefused:
        messages.error(request, "Your account may not check this site's backups.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another operation for this server. Check backups after it "
            "finishes.",
        )
    else:
        messages.success(request, "Barectl is listing this site's recovery points.")
    return redirect("site_backups", pk=pk, identifier=identifier)
