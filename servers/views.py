from copy import copy
from typing import Literal

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from bootstrap import actions
from bootstrap.apply import apply_history
from bootstrap.presentation import ApplyView, PreparationView
from bootstrap.profiles import DRIVER_ACTIONS
from bootstrap.services import preparation_history, read_plans, recorded_plans
from bootstrap.setup import SetupState
from bootstrap.setup import summary as setup_summary
from bootstrap.views import SiteReturn, plans_context, plans_token, return_site
from dashboard.middleware import is_htmx_request
from databases.binding import connection_text
from databases.handler import AUTHORITY as DATABASE_AUTHORITY
from databases.services import read_database_plans, read_site_bindings
from databases.views import database_context, driver_context, site_binding_context
from discovery.presentation import VIEW_APPLICATIONS, VIEW_SITES, present_sites
from discovery.services import recorded_discovery, request_discovery
from sites import names as site_names
from sites.forms import SiteForm
from sites.handler import AUTHORITY as SITE_AUTHORITY
from sites.services import read_site_plans
from sites.views import creation_url, form_for_server, site_context
from tls.forms import SiteInstallationForm
from tls.handler import AUTHORITY as TLS_AUTHORITY
from tls.services import read_site_readiness, read_tls_plans
from tls.views import site_installation_context, site_readiness_context, tls_context
from wordpress.services import read_wordpress_plans
from wordpress.views import wordpress_context

from .activity import site_activity
from .discovery_state import (
    AttemptView,
    DiscoveryState,
    SitePage,
    Status,
    activity_rows,
    inventory,
    server_state,
    site_application,
    site_page,
)
from .forms import ServerForm, ServerSearchForm
from .models import Server
from .registration import RemovalBlocked, SaveOutcome, remove_server, save_server
from .ssh_config import load_aliases


def _is_fragment_request(request: HttpRequest) -> bool:
    # History restores and body-targeted requests need the complete page.
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def _save(form: ServerForm) -> SaveOutcome | None:
    outcome = save_server(form.save(commit=False))
    if outcome is SaveOutcome.TAKEN:
        form.add_error(None, "Another server was saved with this name or alias. Try again.")
    elif outcome is SaveOutcome.BUSY:
        form.add_error(
            "ssh_alias",
            "Barectl is running a remote operation, such as a connection check, with the "
            "current alias. Change it after the operation finishes.",
        )
    else:
        return outcome
    return None


def _server_form(request: HttpRequest, server: Server | None) -> HttpResponse:
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


Section = Literal["overview", "sites", "setup", "activity", "advanced"]
_SECTIONS: dict[Section, str] = {
    "overview": "Overview",
    "sites": "Sites",
    "setup": "Setup",
    "activity": "Activity",
    "advanced": "Advanced",
}

SiteSection = Literal["overview", "database", "https", "wordpress", "activity", "advanced"]


def _discovery_section(request: HttpRequest) -> Section:
    return "advanced" if request.GET.get("section") == "advanced" else "overview"


def _return_site(request: HttpRequest, state: DiscoveryState) -> SiteReturn | None:
    """A validated originating site, or None. Never a caller-supplied URL.

    The identifier must be a name Barectl addresses and appear in the last complete
    observation, so the link never invents a site record.
    """
    if not request.user.has_perm(VIEW_SITES):
        return None
    site_return = return_site(request)
    if site_return is None or not site_page(state, site_return.identifier).found:
        return None
    return site_return


def _discovery_context(request: HttpRequest, state: DiscoveryState) -> dict[str, object]:
    context: dict[str, object] = {"server": state.server, "state": state, "Status": Status}
    if request.user.has_perm(VIEW_SITES):
        context["show_sites"] = True
        if state.snapshot is not None:
            context["sites"] = present_sites(state.snapshot.collected.sites)
    return context


def _discovery_fragment(
    request: HttpRequest,
    server: Server,
    shown: str | None = None,
    *,
    focus: bool = False,
) -> HttpResponse:
    state = server_state(server)
    context = _discovery_context(request, state)
    # After the operator's own action the removed button cannot keep focus; move it to the
    # section heading. Polling responses leave focus alone.
    context["focus"] = focus
    context["section"] = _discovery_section(request)
    # The recorded attempts change when a new one is queued or the shown one's state
    # changes; unchanged polls leave the history alone so it can be read undisturbed.
    attempts_changed = focus
    if state.changed_since(shown):
        context["announcement"] = state.announcement
        # The Status row sits outside the fragment; update it when the state changes.
        context["status"] = state.status
        attempts_changed = True
    if attempts_changed:
        context["history"] = state.history
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
def server_detail(request: HttpRequest, pk: int, section: Section = "overview") -> HttpResponse:
    return server_page(request, pk, section)


def _advanced_sections(request: HttpRequest, server: Server, context: dict[str, object]) -> None:
    """The advanced page's optional workflow sections, each behind its own view authority."""
    if request.user.has_perms(TLS_AUTHORITY.view):
        context.update(tls_context(server, read_tls_plans(server)))
        from tls.installation import PERMISSIONS as INSTALLATION_PERMISSIONS

        context["tls_can_install"] = request.user.has_perms(INSTALLATION_PERMISSIONS)
    if request.user.has_perms(actions.BOOTSTRAP.view):
        context.update(wordpress_context(server, read_wordpress_plans(server)))


def server_page(
    request: HttpRequest,
    pk: int,
    section: Section,
    *,
    site_form: SiteForm | None = None,
    status: int = 200,
) -> HttpResponse:
    """A server section's full page; ``site_form`` keeps a refused site submission's input."""
    server = get_object_or_404(Server, pk=pk)
    state = server_state(server)
    context = _discovery_context(request, state)
    context.update(history=state.history, section=section, section_title=_SECTIONS[section])
    if section == "overview":
        context["site_creation_url"] = creation_url(request.user, server.pk)
    if section == "sites" and not request.user.has_perm(VIEW_SITES):
        raise PermissionDenied
    if section == "activity":
        shown = actions.visible(request.user, actions.every_action())
        rows: list[AttemptView | PreparationView | ApplyView] = list(state.history)
        rows.extend(preparation_history(shown, server))
        rows.extend(apply_history(shown, server))
        rows.sort(key=lambda row: (row.queued_at, row.operation_id), reverse=True)
        context.update(attempts=rows, show_plans=bool(shown))
    if section in ("setup", "advanced") and request.user.has_perms(actions.BOOTSTRAP.view):
        plans = read_plans(server)
        context.update(plans_context(server, plans), token=plans_token(plans))
    if section == "setup":
        context["SetupState"] = SetupState
        context["setup_components"] = setup_summary(
            None if state.snapshot_notice is not None else state.presentation
        )
        context["site_return"] = _return_site(request, state)
        if request.user.has_perms(DATABASE_AUTHORITY.view):
            context.update(driver_context(server, read_plans(server, DRIVER_ACTIONS)))
    if section in ("sites", "advanced") and request.user.has_perms(SITE_AUTHORITY.view):
        context.update(site_context(server, read_site_plans(server), site_form))
    if section == "advanced" and request.user.has_perms(DATABASE_AUTHORITY.view):
        context.update(database_context(server, read_database_plans(server)))
    if section == "advanced":
        _advanced_sections(request, server, context)
    return render(request, "servers/detail.html", context, status=status)


@never_cache
@require_GET
@login_required
@permission_required(("servers.view_server", VIEW_SITES), raise_exception=True)
def site_detail(
    request: HttpRequest, pk: int, identifier: str, section: SiteSection = "overview"
) -> HttpResponse:
    return site_page_response(request, pk, identifier, section)


def site_page_response(
    request: HttpRequest,
    pk: int,
    identifier: str,
    section: SiteSection,
    *,
    installation_form: SiteInstallationForm | None = None,
    status: int = 200,
) -> HttpResponse:
    """A site section's full page; ``installation_form`` keeps a refused submission's input."""
    server = get_object_or_404(Server, pk=pk)
    if not site_names.valid_identifier(identifier):
        raise Http404
    state = server_state(server)
    page: SitePage = site_page(state, identifier)
    context = {
        "server": server,
        "identifier": identifier,
        "state": state,
        "snapshot": state.snapshot,
        "site": page.site,
        "absence": page.absence,
        "site_page": page,
        "section": section,
    }
    if (
        section == "overview"
        and page.site is not None
        and page.site.finishable
        and request.user.has_perms(SITE_AUTHORITY.prepare)
    ):
        context.update(
            site_context(
                server,
                read_site_plans(server),
                form_for_server(
                    server,
                    initial={
                        "identifier": identifier,
                        "names": " ".join(page.site.domains),
                        "php_version": page.site.php_version,
                    },
                    auto_id="id_site_finish_%s",
                ),
            )
        )
        context["site_finish"] = True
    if section == "database" and page.site is not None and page.site.database_engine:
        context["database_connection"] = connection_text(page.site.database_engine, identifier)
    if (
        section == "database"
        and page.site is not None
        and request.user.has_perms(DATABASE_AUTHORITY.view)
    ):
        context.update(
            site_binding_context(
                server, identifier, read_site_bindings(server, identifier), page.site
            )
        )
    if section == "https" and page.site is not None and request.user.has_perms(TLS_AUTHORITY.view):
        context.update(
            site_readiness_context(server, identifier, read_site_readiness(server, identifier))
        )
        context.update(
            site_installation_context(server, identifier, request.user, form=installation_form)
        )
    if section == "wordpress":
        if not request.user.has_perm(VIEW_APPLICATIONS):
            raise PermissionDenied
        context["wpapp_application"] = site_application(state, identifier)
    if section == "activity":
        shown = actions.visible(request.user, actions.every_action())
        context.update(activity=site_activity(server, identifier, shown), show_plans=bool(shown))
    return render(request, "sites/detail.html", context, status=status)


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def activity(request: HttpRequest) -> HttpResponse:
    rows: list[AttemptView | PreparationView | ApplyView] = list(activity_rows())
    shown = actions.visible(request.user, actions.every_action())
    show_plans = bool(shown)
    if show_plans:
        rows.extend(preparation_history(shown))
        rows.extend(apply_history(shown))
        rows.sort(key=lambda row: (row.queued_at, row.operation_id), reverse=True)
    return render(request, "servers/activity.html", {"attempts": rows, "show_plans": show_plans})


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def server_discovery(request: HttpRequest, pk: int) -> HttpResponse:
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
            messages.success(request, f"Removed {name} and its local history from Barectl.")
            return redirect("servers")
    shown = actions.visible(request.user, actions.every_action())
    context = {
        "server": server,
        "recorded": recorded_discovery(server),
        "plan_count": recorded_plans(server, shown),
        "shows_plans": bool(shown),
        "refused": refused,
    }
    # A refused removal conflicts with discovery, even one that has finished since.
    return render(request, "servers/remove.html", context, status=409 if refused else 200)
