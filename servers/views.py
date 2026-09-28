from copy import copy

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.db.models import Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from dashboard.middleware import is_htmx_request
from discovery.services import history, recorded_discovery, request_discovery

from .discovery_state import DiscoveryState, Status, inventory, server_state
from .forms import ServerForm, ServerSearchForm
from .models import Server
from .registration import RemovalBlocked, SaveOutcome, remove_server, save_server
from .ssh_config import load_aliases


def _is_fragment_request(request: HttpRequest) -> bool:
    # History restores and body-targeted requests need the complete page.
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def _save(form: ServerForm) -> SaveOutcome | None:
    """Save the form's server, or report on the form why it was not saved.

    Raises ``Server.DoesNotExist`` when another request removed the edited server.
    """
    outcome = save_server(form.save(commit=False))
    if outcome is SaveOutcome.TAKEN:
        form.add_error(None, "Another server was saved with this name or alias. Try again.")
    elif outcome is SaveOutcome.BUSY:
        form.add_error(
            "ssh_alias",
            "Barectl is checking the connection with the current alias. Change it after the "
            "check finishes.",
        )
    else:
        return outcome
    return None


def _server_form(request: HttpRequest, server: Server | None) -> HttpResponse:
    """Registration and editing share one form; only the wording differs."""
    # Read on every request: the operator may change the controller's configuration.
    catalog = load_aliases(settings.SSH_CONFIG_PATH)
    # The form updates its instance while validating; the page shows the saved values.
    saved = copy(server)
    form = ServerForm(request.POST or None, instance=server, catalog=catalog)
    outcome = None
    if request.method == "POST" and form.is_valid():
        try:
            outcome = _save(form)
        except Server.DoesNotExist:
            # Removed by another request after this one loaded it.
            raise Http404 from None
    if outcome is not None:
        result = form.instance
        verb = "Saved" if saved else "Registered"
        if outcome is SaveOutcome.QUEUED:
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
        "alias_unavailable": saved is not None and saved.ssh_alias not in catalog,
    }
    return render(request, "servers/form.html", context)


def _discovery_context(state: DiscoveryState) -> dict[str, object]:
    return {"server": state.server, "state": state, "Status": Status}


def _discovery_fragment(
    request: HttpRequest,
    server: Server,
    shown: str | None = None,
    *,
    focus: bool = False,
) -> HttpResponse:
    state = server_state(server)
    context = _discovery_context(state)
    # After the operator's own action the removed button cannot keep focus; move it to the
    # section heading. Polling responses leave focus alone.
    context["focus"] = focus
    # The recorded attempts change when a new one is queued or the shown one's state
    # changes; unchanged polls leave the history alone so it can be read undisturbed.
    attempts_changed = focus
    if state.changed_since(shown):
        context["announcement"] = state.announcement
        # The Status row sits outside the fragment; update it when the state changes.
        context["status"] = state.status
        attempts_changed = True
    if attempts_changed:
        context["history"] = state.history()
    response = render(request, "servers/_discovery_update.html", context)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@login_required
@permission_required("servers.view_server", raise_exception=True)
def server_list(request: HttpRequest) -> HttpResponse:
    form = ServerSearchForm(request.GET)
    query = form.cleaned_data["q"] if form.is_valid() else ""
    servers = Server.objects.all()
    if query:
        servers = servers.filter(Q(name__icontains=query) | Q(ssh_alias__icontains=query))
    context = {
        "form": form,
        "query": query,
        "rows": inventory(servers),
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
    state = server_state(server)
    context = _discovery_context(state)
    # Every recorded attempt stays reviewable, newest first, whatever became of it.
    context["history"] = state.history()
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
    return render(request, "servers/activity.html", {"attempts": history()})


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
    return _discovery_fragment(request, server, request.GET.get("shown"))


@require_POST
@login_required
@permission_required(
    ("servers.view_server", "discovery.add_discoveryattempt"), raise_exception=True
)
def server_verify(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    try:
        request_discovery(server)
    except Server.DoesNotExist:
        # Removed by another request after this one loaded it.
        raise Http404 from None
    if _is_fragment_request(request):
        return _discovery_fragment(request, server, focus=True)
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
    context = {"server": server, "recorded": recorded_discovery(server), "refused": refused}
    # A refused removal conflicts with discovery, even one that has finished since.
    return render(request, "servers/remove.html", context, status=409 if refused else 200)
