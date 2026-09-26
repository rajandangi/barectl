from collections.abc import Collection
from copy import copy
from dataclasses import dataclass
from enum import StrEnum

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache

from dashboard.middleware import is_htmx_request

from .forms import ServerForm, ServerSearchForm
from .models import Server
from .ssh_config import AliasCatalog, load_aliases


class Status(StrEnum):
    NEEDS_ALIAS = "Needs SSH alias"
    UNAVAILABLE = "SSH alias unavailable"
    NOT_VERIFIED = "Not verified"


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


def _save(form: ServerForm) -> Server | None:
    """Save, or report a registration that took the alias after validation."""
    try:
        with transaction.atomic():
            return form.save()
    except IntegrityError:
        form.add_error(None, "Another server was saved with this name or alias. Try again.")
        return None


def _status(server: Server, catalog: AliasCatalog) -> Status:
    # No registration claims SSH connectivity; nothing has connected yet.
    if server.needs_alias:
        return Status.NEEDS_ALIAS
    if server.ssh_alias not in catalog:
        return Status.UNAVAILABLE
    return Status.NOT_VERIFIED


def _server_form(request: HttpRequest, server: Server | None) -> HttpResponse:
    """Registration and editing share one form; only the wording differs."""
    catalog = _controller_aliases()
    # The form updates its instance while validating; the page shows the saved values.
    saved = copy(server)
    form = ServerForm(request.POST or None, instance=server, catalog=catalog)
    if request.method == "POST" and form.is_valid() and (result := _save(form)):
        verb = "Saved" if saved else "Registered"
        messages.success(
            request,
            f"{verb} {result.name} with SSH alias {result.ssh_alias}. "
            "Barectl has not verified the connection.",
        )
        return redirect("servers")
    context = {
        "form": form,
        "catalog": catalog,
        "server": saved,
        "title": f"Edit {saved.name}" if saved else "Add server",
        "submit_label": "Save changes" if saved else "Register server",
        "alias_unavailable": saved is not None and _status(saved, catalog) == Status.UNAVAILABLE,
    }
    return render(request, "servers/form.html", context)


@never_cache
@login_required
@permission_required("servers.view_server", raise_exception=True)
def server_list(request: HttpRequest) -> HttpResponse:
    form = ServerSearchForm(request.GET)
    query = form.cleaned_data["q"] if form.is_valid() else ""
    servers = Server.objects.all()
    if query:
        servers = servers.filter(Q(name__icontains=query) | Q(ssh_alias__icontains=query))
    servers_list = list(servers)
    # Resolve only the aliases shown, not every Host entry in the configuration.
    catalog = _controller_aliases({server.ssh_alias for server in servers_list})
    counts = Server.objects.aggregate(
        total=Count("pk"), unreconciled=Count("pk", filter=Q(ssh_alias=""))
    )
    context = {
        "form": form,
        "query": query,
        "rows": [ServerRow(server, _status(server, catalog)) for server in servers_list],
        "total_count": counts["total"],
        "unreconciled_count": counts["unreconciled"],
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
