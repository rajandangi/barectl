"""The site Backups section and its three actions (Phase D #396, #179)."""

import contextlib
from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import FileResponse, Http404, HttpRequest, HttpResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from discovery.presentation import VIEW_SITES
from discovery.snapshot import Snapshot
from operations import preparation, services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from servers.preparation import server_facts
from sites.bodies.common import SITE_GATED
from sites.names import valid_identifier
from sites.preparation import site_facts

from . import check, convention, downloads, integrity, presentation, retention, schedule
from .change import BACKUP_SLUG, ENABLE_SLUG, FULL_SLUG
from .export import SLUG as EXPORT_SLUG
from .models import BackupExport
from .offsite import COPY_SLUG
from .preparation import BASE, DESTRUCTIVE, ENABLE, EXPORT, REOPEN
from .removed import SLUG as DELETE_REMOVED_SLUG
from .reopen import SLUG as REOPEN_SLUG
from .restore import SCOPES
from .restore import SLUG as RESTORE_SLUG

if TYPE_CHECKING:
    from discovery.snapshot import ObservedSite


def _site(state: DiscoveryState, identifier: str) -> tuple[Snapshot | None, ObservedSite | None]:
    snapshot = state.snapshot
    if snapshot is None:
        return None, None
    return snapshot, state.site(identifier)


def _target(snapshot: Snapshot | None, site: ObservedSite | None) -> bool:
    return site is not None and site.file == f"/etc/caddy/sites/{site.identifier}.caddy"


def _offered(decision: preparation.Decision, data: bool, data_reason: str) -> tuple[bool, str]:
    """Whether a card is offered, and the one sentence that explains its absence."""
    if not decision.allowed:
        return False, decision.sentence
    if not data:
        return False, data_reason
    return True, ""


def context_for_site(
    state: DiscoveryState, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    """Everything the Backups section shows, from stored rows only; no SSH."""
    server = state.server
    snapshot = state.snapshot
    site = state.site(identifier)
    collected = snapshot.collected if snapshot is not None else None
    latest = check.latest_check(server, identifier)
    active = check.active(server, identifier)
    gated = site is not None and SITE_GATED in site.missing
    view = presentation.view(
        site,
        collected,
        identifier,
        latest,
        checking=active is not None,
        gated=gated,
        integrity=integrity.stored(server, identifier),
        removed=check.latest_removed(server),
        schedule=schedule.stored(server, identifier),
    )
    downloads.expire(server, identifier)
    facts = server_facts(state, user)
    observed = site_facts(state, identifier)
    target = observed.convention
    managed = target and observed.shape is preparation.SiteShape.MANAGED

    def decide(requirements: preparation.Requirements) -> preparation.Decision:
        return preparation.decide(facts, observed, requirements)

    base = decide(BASE)
    enable = decide(ENABLE)
    reopen = decide(REOPEN)
    destructive = decide(DESTRUCTIVE)
    export = decide(EXPORT)
    enabled = view.enabled
    offsite = collected.offsite.value if collected is not None else None
    sources = []
    if offsite is not None and offsite.configured:
        for source in offsite.sources:
            points = presentation.connected_points_view(source) if source.read else ()
            sources.append(
                {
                    "identifier": source.identifier,
                    "points": points,
                    "problem": source.problem,
                }
            )
    context: dict[str, object] = {
        "backups": view,
        "backups_sources": sources,
        "backups_exports": tuple(
            BackupExport.objects.filter(server=server, identifier=identifier)
            .exclude(status=BackupExport.Status.CANCELLED)
            .order_by("-created_at", "-pk")[:5]
        ),
        "backups_target": target,
        "backups_site_reason": base.sentence,
        "backups_can_download": user.has_perms(
            ("servers.view_server", VIEW_SITES, "operations.change_shared")
        ),
        "backups_can_check": bool(
            managed and user.has_perms((*check.READ_PERMISSIONS, VIEW_SITES))
        ),
        "backups_database_reason": ("" if view.database else view.database_reason),
        "backups_kit_lines": presentation.kit_lines(server.name, identifier, collected),
    }
    context["backups_can_enable"], context["backups_enable_reason"] = _offered(enable, True, "")
    context["backups_can_back_up"], context["backups_back_up_reason"] = _offered(
        base,
        enabled and view.database,
        view.database_reason or "Enable backups before taking a backup.",
    )
    context["backups_can_back_up_full"], context["backups_back_up_full_reason"] = _offered(
        base, enabled, "Enable backups before taking a backup."
    )
    context["backups_can_copy"], context["backups_copy_reason"] = _offered(
        base,
        enabled and view.offsite is not None,
        "Enable backups and set up offsite storage before copying a point offsite.",
    )
    context["backups_can_reopen"], context["backups_reopen_reason"] = _offered(
        reopen,
        view.reopen,
        "This site is not paused by a full backup, so there is nothing to reopen.",
    )
    context["backups_can_restore"], context["backups_restore_reason"] = _offered(
        destructive, enabled, "Enable backups before restoring a recovery point."
    )
    context["backups_can_delete_removed"], context["backups_delete_removed_reason"] = _offered(
        destructive, True, ""
    )
    context["backups_can_export"], context["backups_export_reason"] = _offered(
        export, enabled, "Enable backups before exporting a recovery point."
    )
    context["backups_can_set_retention"], context["backups_set_retention_reason"] = _offered(
        destructive, enabled, "Enable backups before setting retention."
    )
    context["backups_can_keep"], context["backups_keep_reason"] = _offered(
        base, enabled, "Enable backups before keeping a recovery point."
    )
    retention.context_for_site(server, identifier, context)
    schedule.context_for_site(server, identifier, context)
    return context


@never_cache
@require_GET
@login_required
@permission_required(("servers.view_server", VIEW_SITES), raise_exception=True)
def recovery_kit(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    snapshot, site = _site(server_state(server), identifier)
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
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
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
def prepare_back_up_first(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """A paused Full site capture from a Deploy's confirm screen (#358, #407).

    It is the ordinary Full site review with one recorded input, so a successful run
    offers Continue to Deploy; the engine chains nothing.
    """
    return _prepare(request, pk, identifier, FULL_SLUG, "site_deployments", before_deploy=True)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_reopen(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    return _prepare(request, pk, identifier, REOPEN_SLUG, "site_backups")


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_copy(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Copy one recovery point offsite again; the point is the one the operator chose."""
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    point = request.POST.get("point", "")
    if convention.POINT.fullmatch(point) is None:
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server_state(server), identifier, request.user)
    if not context["backups_can_copy"]:
        messages.error(request, str(context["backups_copy_reason"]))
        return redirect("site_backups", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            COPY_SLUG,
            inputs={"version": 1, "identifier": identifier, "point": point},
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare again.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_retention(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Set how long this site's recovery points are kept."""
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    days = request.POST.get("days", "")
    if not days.isdigit() or int(days) not in convention.RETENTION_DAYS:
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server_state(server), identifier, request.user)
    if not context["backups_can_set_retention"]:
        messages.error(request, str(context["backups_set_retention_reason"]))
        return redirect("site_backups", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            retention.SET_SLUG,
            inputs={"version": 1, "identifier": identifier, "days": int(days)},
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare again.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_disable_retention(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Turn retention off without deleting anything."""
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    state = server_state(server)
    context = context_for_site(state, identifier, request.user)
    if not context["backups_can_disable_retention"]:
        messages.error(request, str(context["backups_disable_retention_reason"]))
        return redirect("site_backups", pk=pk, identifier=identifier)
    return _prepare(request, pk, identifier, retention.DISABLE_SLUG, "site_backups", state=state)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_keep(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Toggle one recovery point's keep tag; nothing is deleted."""
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    point = request.POST.get("point", "")
    if convention.POINT.fullmatch(point) is None:
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server_state(server), identifier, request.user)
    if not context["backups_can_keep"]:
        messages.error(request, str(context["backups_keep_reason"]))
        return redirect("site_backups", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            retention.KEEP_SLUG,
            inputs={"version": 1, "identifier": identifier, "point": point},
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare again.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_restore(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    point = request.POST.get("point", "")
    scope = request.POST.get("scope", "database")
    source = request.POST.get("source", "")
    if convention.POINT.fullmatch(point) is None or scope not in SCOPES:
        raise Http404
    state: DiscoveryState | None = None
    if source:
        # A source is either a connected offsite source or a repository the last explicit
        # read listed as removed (#407, #408). The site is never its own removed source.
        if not valid_identifier(source):
            raise Http404
        server = get_object_or_404(Server, pk=pk)
        listed = {str(row.get("identifier")) for row in check.latest_removed(server)}
        state = server_state(server)
        snapshot = state.snapshot
        offsite = snapshot.collected.offsite.value if snapshot is not None else None
        connected = {row.identifier for row in offsite.sources} if offsite is not None else set()
        if source not in listed and source not in connected:
            raise Http404
        if source in listed and source == identifier:
            raise Http404
    return _prepare(
        request,
        pk,
        identifier,
        RESTORE_SLUG,
        "site_backups",
        point=point,
        scope=scope,
        source=source,
        state=state,
    )


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_delete_removed(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Delete the kept backups of a removed site; only a reviewed Destructive change does."""
    source = request.POST.get("source", "")
    if not valid_identifier(identifier) or not valid_identifier(source):
        raise Http404
    if not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    listed = {str(row.get("identifier")) for row in check.latest_removed(server)}
    if source not in listed:
        raise Http404
    context = context_for_site(server_state(server), identifier, request.user)
    if not context["backups_can_delete_removed"]:
        messages.error(request, str(context["backups_delete_removed_reason"]))
        return redirect("site_backups", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            DELETE_REMOVED_SLUG,
            inputs={"version": 1, "identifier": source},
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare again.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_export(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Export one recovery point to this computer; moving the data needs Shared consent."""
    point = request.POST.get("point", "")
    if convention.POINT.fullmatch(point) is None:
        raise Http404
    return _prepare(request, pk, identifier, EXPORT_SLUG, "site_backups", point=point)


def _prepare(  # noqa: C901 - one guarded preparation
    request: HttpRequest,
    pk: int,
    identifier: str,
    slug: str,
    target: str,
    *,
    point: str = "",
    scope: str = "database",
    source: str = "",
    before_deploy: bool = False,
    state: DiscoveryState | None = None,
) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(state or server_state(server), identifier, request.user)
    if slug == ENABLE_SLUG and not context["backups_can_enable"]:
        messages.error(request, str(context["backups_enable_reason"]))
        return redirect(target, pk=pk, identifier=identifier)
    if slug == BACKUP_SLUG and not context["backups_can_back_up"]:
        messages.error(request, str(context["backups_back_up_reason"]))
        return redirect(target, pk=pk, identifier=identifier)
    if slug == FULL_SLUG and not context["backups_can_back_up_full"]:
        messages.error(request, str(context["backups_back_up_full_reason"]))
        return redirect(target, pk=pk, identifier=identifier)
    if slug == REOPEN_SLUG and not context["backups_can_reopen"]:
        messages.error(request, str(context["backups_reopen_reason"]))
        return redirect(target, pk=pk, identifier=identifier)
    if slug == RESTORE_SLUG and not context["backups_can_restore"]:
        messages.error(request, str(context["backups_restore_reason"]))
        return redirect(target, pk=pk, identifier=identifier)
    if slug == EXPORT_SLUG and not context["backups_can_export"]:
        messages.error(request, str(context["backups_export_reason"]))
        return redirect(target, pk=pk, identifier=identifier)
    inputs: dict[str, object] = {"version": 1, "identifier": identifier}
    if slug in (RESTORE_SLUG, EXPORT_SLUG):
        inputs["point"] = point
    if slug == RESTORE_SLUG:
        if scope != "database":
            inputs["scope"] = scope
        if source:
            inputs["source"] = source
    if before_deploy:
        inputs["from_deploy"] = True
    try:
        queued = services.request_prepare(
            server,
            request.user,
            slug,
            inputs=inputs,
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
    context = context_for_site(server_state(server), identifier, request.user)
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


class _Served:
    """A one-shot download: closing the response removes the staged file."""

    def __init__(self, path: object) -> None:
        import pathlib

        self._path = pathlib.Path(str(path))
        self._handle = self._path.open("rb")
        self.name = self._path.name

    def read(self, size: int = -1) -> bytes:
        return self._handle.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._handle.seek(offset, whence)

    def tell(self) -> int:
        return self._handle.tell()

    def close(self) -> None:
        self._handle.close()
        with contextlib.suppress(OSError):
            self._path.unlink()
        with contextlib.suppress(OSError):
            self._path.parent.rmdir()


def _export_row(request: HttpRequest, pk: int, token: str) -> tuple[Server, BackupExport]:
    if isinstance(request.user, AnonymousUser):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    downloads.expire(server)
    row = BackupExport.objects.filter(server=server, token=token).first()
    if row is None or row.status != BackupExport.Status.READY or row.expired:
        raise Http404
    return server, row


@never_cache
@require_GET
@login_required
@permission_required(
    ("servers.view_server", VIEW_SITES, "operations.change_shared"), raise_exception=True
)
def download_export(
    request: HttpRequest, pk: int, token: str, artifact: str
) -> StreamingHttpResponse:
    """Serve one export artifact from private staging; never connect to the server."""
    if downloads.TOKEN.fullmatch(token) is None or artifact not in downloads.ARTIFACTS:
        raise Http404
    _server, row = _export_row(request, pk, token)
    if artifact == "files" and not row.has_files:
        raise Http404
    if artifact == "database" and not row.has_database:
        raise Http404
    try:
        path = downloads.served(row, artifact)
    except FileNotFoundError:
        raise Http404 from None
    downloads.mark_served(row, artifact)
    name = (
        f"{row.identifier}-{row.point}-files.tar"
        if artifact == "files"
        else f"{row.identifier}-{row.point}-database.sql"
    )
    response = FileResponse(
        _Served(path),
        as_attachment=True,
        filename=name,
        content_type="application/x-tar" if artifact == "files" else "application/sql",
    )
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_POST
@login_required
@permission_required(
    ("servers.view_server", VIEW_SITES, "operations.change_shared"), raise_exception=True
)
def cancel_export(request: HttpRequest, pk: int, token: str) -> HttpResponse:
    """Delete an export's private staging now; nothing on the server remains."""
    if downloads.TOKEN.fullmatch(token) is None:
        raise Http404
    server, row = _export_row(request, pk, token)
    downloads.cancel(row)
    messages.success(request, "Barectl removed this export's copy from this computer.")
    return redirect("site_backups", pk=server.pk, identifier=row.identifier)
