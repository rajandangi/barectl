from dataclasses import dataclass

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache

from dashboard.middleware import is_htmx_request

from .forms import ServerForm, ServerSearchForm
from .models import Server
from .ssh_config import AliasCatalog, load_aliases


@dataclass(frozen=True)
class ServerRow:
    server: Server
    status: str


def _is_fragment_request(request: HttpRequest) -> bool:
    # History restores and body-targeted requests need the complete page.
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def _controller_aliases() -> AliasCatalog:
    # Read on every request: the operator may change the controller's configuration.
    return load_aliases(settings.SSH_CONFIG_PATH)


def _status(server: Server, catalog: AliasCatalog) -> str:
    # No registration claims SSH connectivity; nothing has connected yet.
    if server.needs_alias:
        return "Needs SSH alias"
    if server.ssh_alias not in catalog:
        return "SSH alias unavailable"
    return "Not verified"


@never_cache
@login_required
@permission_required("servers.view_server", raise_exception=True)
def server_list(request: HttpRequest) -> HttpResponse:
    form = ServerSearchForm(request.GET)
    query = form.cleaned_data["q"] if form.is_valid() else ""
    servers = Server.objects.all()
    if query:
        servers = servers.filter(Q(name__icontains=query) | Q(ssh_alias__icontains=query))
    catalog = _controller_aliases()
    rows = [ServerRow(server, _status(server, catalog)) for server in servers]
    context = {
        "form": form,
        "query": query,
        "rows": rows,
        "total_count": Server.objects.count(),
        "unreconciled_count": Server.objects.filter(ssh_alias="").count(),
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
    catalog = _controller_aliases()
    form = ServerForm(request.POST or None, catalog=catalog)
    if request.method == "POST" and form.is_valid():
        server = form.save()
        messages.success(
            request,
            f"Registered {server.name} with SSH alias {server.ssh_alias}. "
            "Barectl has not connected to it yet.",
        )
        return redirect("servers")
    return render(request, "servers/form.html", {"form": form, "catalog": catalog})


@never_cache
@login_required
@permission_required(("servers.view_server", "servers.change_server"), raise_exception=True)
def server_edit(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    # The form updates its instance while validating; keep the saved values for the page.
    saved = Server(name=server.name, ssh_alias=server.ssh_alias)
    saved.legacy_connection = server.legacy_connection
    catalog = _controller_aliases()
    form = ServerForm(request.POST or None, instance=server, catalog=catalog)
    if request.method == "POST" and form.is_valid():
        server = form.save()
        messages.success(
            request,
            f"Saved {server.name} with SSH alias {server.ssh_alias}. "
            "Barectl has not verified the connection.",
        )
        return redirect("servers")
    context = {
        "form": form,
        "catalog": catalog,
        "server": saved,
        "alias_unavailable": bool(saved.ssh_alias) and saved.ssh_alias not in catalog,
    }
    return render(request, "servers/form.html", context)
