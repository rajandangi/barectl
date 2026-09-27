from collections.abc import Collection
from copy import copy
from dataclasses import dataclass
from enum import StrEnum

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.db import DatabaseError, IntegrityError, transaction
from django.db.models import OuterRef, Q, Subquery
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from dashboard.middleware import is_htmx_request
from discovery.models import DiscoveryAttempt, DiscoverySnapshot
from discovery.services import (
    DiscoveryBusy,
    RemovalBlocked,
    queue_discovery,
    recover_stale_attempts,
    remove_server,
    request_discovery,
)

from .forms import ServerForm, ServerSearchForm
from .models import Server
from .ssh_config import AliasCatalog, load_aliases

AttemptStatus = DiscoveryAttempt.Status


class Status(StrEnum):
    UNAVAILABLE = "SSH alias unavailable"
    NOT_VERIFIED = "Not verified"
    QUEUED = "Connection check queued"
    RUNNING = "Checking connection"
    FAILED = "Connection failed"
    VERIFIED = "Verified"


ATTEMPT_STATUS = {
    AttemptStatus.QUEUED: Status.QUEUED,
    AttemptStatus.RUNNING: Status.RUNNING,
    AttemptStatus.FAILED: Status.FAILED,
    AttemptStatus.SUCCEEDED: Status.VERIFIED,
}
# Announced in the page's live region when an attempt's state changes.
ANNOUNCEMENTS = {
    AttemptStatus.QUEUED: "Connection check queued.",
    AttemptStatus.RUNNING: "Checking the connection.",
    AttemptStatus.FAILED: "The connection failed.",
    AttemptStatus.SUCCEEDED: (
        "Connection verified. Operating system and capacity observations are ready."
    ),
}


@dataclass(frozen=True)
class ServerRow:
    server: Server
    status: Status


def _is_fragment_request(request: HttpRequest) -> bool:
    # History restores and body-targeted requests need the complete page.
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def _controller_aliases(names: Collection[str] | None = None) -> AliasCatalog:
    # Read on every request: the operator may change the controller's configuration.
    return load_aliases(settings.SSH_CONFIG_PATH, names)


def _save(form: ServerForm, previous_alias: str) -> Server | None:
    """Save, queueing a connection check when the alias is new, or report a conflict.

    Raises ``Server.DoesNotExist`` when another request removed the edited server.
    """
    server = form.save(commit=False)
    editing = server.pk is not None
    try:
        with transaction.atomic():
            # An edit only updates: saving a removed server must not insert it again.
            server.save(force_update=editing)
            if server.ssh_alias != previous_alias:
                queue_discovery(server)
            return server
    except IntegrityError:
        form.add_error(None, "Another server was saved with this name or alias. Try again.")
    except DiscoveryBusy:
        form.add_error(
            "ssh_alias",
            "Barectl is checking the connection with the current alias. Change it after the "
            "check finishes.",
        )
    except DatabaseError:
        if editing and not Server.objects.filter(pk=server.pk).exists():
            raise Server.DoesNotExist from None
        raise
    return None


def _alias_unavailable(server: Server, catalog: AliasCatalog) -> bool:
    return server.ssh_alias not in catalog


def _status(server: Server, catalog: AliasCatalog, attempt: str | None) -> Status:
    if attempt in DiscoveryAttempt.ACTIVE:
        return ATTEMPT_STATUS[AttemptStatus(attempt)]
    if _alias_unavailable(server, catalog):
        return Status.UNAVAILABLE
    # Registration alone never claims connectivity; only a completed check does.
    return ATTEMPT_STATUS[AttemptStatus(attempt)] if attempt else Status.NOT_VERIFIED


def _server_form(request: HttpRequest, server: Server | None) -> HttpResponse:
    """Registration and editing share one form; only the wording differs."""
    catalog = _controller_aliases()
    # The form updates its instance while validating; the page shows the saved values.
    saved = copy(server)
    previous_alias = saved.ssh_alias if saved else ""
    form = ServerForm(request.POST or None, instance=server, catalog=catalog)
    result = None
    if request.method == "POST" and form.is_valid():
        try:
            result = _save(form, previous_alias)
        except Server.DoesNotExist:
            # Removed by another request after this one loaded it.
            raise Http404 from None
    if result is not None:
        verb = "Saved" if saved else "Registered"
        if result.ssh_alias != previous_alias:
            messages.success(
                request,
                f"{verb} {result.name} with SSH alias {result.ssh_alias}. "
                "Barectl queued a connection check.",
            )
        else:
            messages.success(request, f"{verb} {result.name}.")
        return redirect("server_detail", pk=result.pk)
    context = {
        "form": form,
        "catalog": catalog,
        "server": saved,
        "title": f"Edit {saved.name}" if saved else "Add server",
        "submit_label": "Save changes" if saved else "Register server",
        "alias_unavailable": saved is not None and _alias_unavailable(saved, catalog),
    }
    return render(request, "servers/form.html", context)


def _action_label(attempt: DiscoveryAttempt | None) -> str:
    if attempt is None:
        return "Verify connection"
    if attempt.status == AttemptStatus.FAILED:
        return "Retry connection check"
    if attempt.status == AttemptStatus.SUCCEEDED:
        return "Refresh observations"
    return "Verify connection"


def _discovery_context(
    request: HttpRequest, server: Server, attempt: DiscoveryAttempt | None
) -> dict[str, object]:
    snapshot = (
        DiscoverySnapshot.objects.filter(server=server)
        .select_related("attempt")
        .prefetch_related("components", "nginx_site_files", "php_fpm_pools")
        .first()
    )
    can_verify = request.user.has_perm("discovery.add_discoveryattempt") and (
        attempt is None or not attempt.is_active
    )
    return {
        "server": server,
        "attempt": attempt,
        "snapshot": snapshot,
        "can_verify": can_verify,
        "action_label": _action_label(attempt),
    }


def _discovery_fragment(
    request: HttpRequest,
    server: Server,
    attempt: DiscoveryAttempt | None,
    shown: str | None = None,
    *,
    focus: bool = False,
) -> HttpResponse:
    context = _discovery_context(request, server, attempt)
    # After the operator's own action the removed button cannot keep focus; move it to the
    # section heading. Polling responses leave focus alone.
    context["focus"] = focus
    # The recorded attempts change when a new one is queued or the shown one's state
    # changes; unchanged polls leave the history alone so it can be read undisturbed.
    attempts_changed = focus
    if attempt is not None and attempt.status != shown:
        context["announcement"] = ANNOUNCEMENTS[AttemptStatus(attempt.status)]
        # The Status row sits outside the fragment; update it when the state changes.
        catalog = _controller_aliases({server.ssh_alias})
        context["status"] = _status(server, catalog, attempt.status)
        attempts_changed = True
    if attempts_changed:
        context["history"] = server.discovery_attempts.select_related("snapshot")
    response = render(request, "servers/_discovery_update.html", context)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@login_required
@permission_required("servers.view_server", raise_exception=True)
def server_list(request: HttpRequest) -> HttpResponse:
    form = ServerSearchForm(request.GET)
    query = form.cleaned_data["q"] if form.is_valid() else ""
    # An attempt abandoned by a stopped worker must not show a server as busy forever.
    recover_stale_attempts()
    latest = DiscoveryAttempt.objects.filter(server=OuterRef("pk")).values("status")[:1]
    servers = Server.objects.annotate(attempt_status=Subquery(latest))
    if query:
        servers = servers.filter(Q(name__icontains=query) | Q(ssh_alias__icontains=query))
    servers_list = list(servers)
    # Resolve only the aliases shown, not every Host entry in the configuration.
    catalog = _controller_aliases({server.ssh_alias for server in servers_list})
    context = {
        "form": form,
        "query": query,
        "rows": [
            ServerRow(server, _status(server, catalog, server.attempt_status))
            for server in servers_list
        ],
        "total_count": Server.objects.count(),
    }
    template = "servers/_results.html" if _is_fragment_request(request) else "servers/list.html"
    response = render(request, template, context)
    # The same URL returns a fragment or a page; caches must keep them apart.
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@login_required
@permission_required(("servers.view_server", "servers.add_server"), raise_exception=True)
def server_add(request: HttpRequest) -> HttpResponse:
    return _server_form(request, None)


@never_cache
@login_required
@permission_required(("servers.view_server", "servers.change_server"), raise_exception=True)
def server_edit(request: HttpRequest, pk: int) -> HttpResponse:
    return _server_form(request, get_object_or_404(Server, pk=pk))


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def server_detail(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    catalog = _controller_aliases({server.ssh_alias})
    recover_stale_attempts()
    attempt = server.discovery_attempts.first()
    context = _discovery_context(request, server, attempt)
    context["status"] = _status(server, catalog, attempt.status if attempt else None)
    context["alias_unavailable"] = _alias_unavailable(server, catalog)
    # Every recorded attempt stays reviewable, newest first, whatever became of it.
    context["history"] = server.discovery_attempts.select_related("snapshot")
    return render(request, "servers/detail.html", context)


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def activity(request: HttpRequest) -> HttpResponse:
    """Every recorded discovery attempt across servers, newest recorded first.

    Reviewing activity distinguishes each attempt's outcome from the snapshot its success
    published, so a failed or interrupted attempt is never hidden by earlier results.
    """
    # An attempt abandoned by a stopped worker must not be listed as running forever.
    recover_stale_attempts()
    attempts = DiscoveryAttempt.objects.select_related("server", "snapshot")
    return render(request, "servers/activity.html", {"attempts": attempts})


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def server_discovery(request: HttpRequest, pk: int) -> HttpResponse:
    """The connection and snapshot fragment, polled while an attempt is active."""
    server = get_object_or_404(Server, pk=pk)
    if not _is_fragment_request(request):
        return redirect("server_detail", pk=pk)
    # Polling ends once an abandoned attempt is recovered, and the operator can retry.
    recover_stale_attempts()
    return _discovery_fragment(
        request, server, server.discovery_attempts.first(), request.GET.get("shown")
    )


@require_POST
@login_required
@permission_required(
    ("servers.view_server", "discovery.add_discoveryattempt"), raise_exception=True
)
def server_verify(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    try:
        attempt = request_discovery(server)
    except Server.DoesNotExist:
        # Removed by another request after this one loaded it.
        raise Http404 from None
    if _is_fragment_request(request):
        return _discovery_fragment(request, server, attempt, focus=True)
    messages.success(request, f"Barectl queued a connection check for {server.name}.")
    return redirect("server_detail", pk=pk)


@never_cache
@require_http_methods(["GET", "POST"])
@login_required
@permission_required(("servers.view_server", "servers.delete_server"), raise_exception=True)
def server_remove(request: HttpRequest, pk: int) -> HttpResponse:
    """Confirm, then delete the registration and its local discovery history."""
    server = get_object_or_404(Server, pk=pk)
    refused = False
    # The confirming button submits this field; any other request only shows the page.
    if request.method == "POST" and request.POST.get("confirm") == "remove":
        name = server.name
        try:
            remove_server(server)
        except RemovalBlocked:
            refused = True
        else:
            messages.success(request, f"Removed {name} and its discovery history from Barectl.")
            return redirect("servers")
    else:
        recover_stale_attempts()
    # Only the latest attempt can be active.
    attempt = server.discovery_attempts.first()
    context = {
        "server": server,
        "busy": attempt is not None and attempt.is_active,
        "refused": refused,
        "attempt_count": server.discovery_attempts.count(),
        "has_snapshot": server.snapshots.exists(),
    }
    # A refused removal conflicts with discovery, even one that has finished since.
    return render(request, "servers/remove.html", context, status=409 if refused else 200)
