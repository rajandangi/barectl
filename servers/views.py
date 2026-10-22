from copy import copy
from typing import Literal

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from bootstrap import foundation_setup
from bootstrap.standing import Standing
from dashboard.middleware import is_htmx_request
from discovery.presentation import VIEW_SITES, present_sites
from discovery.services import recorded_discovery, request_discovery
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from operations.presentation import blocking_operation
from runtimes.presentation import shown_catalog
from sites import names as site_names
from sites.forms import HttpSiteForm, LaravelSiteForm, WordPressSiteForm
from sites.recognition import site_files, site_pools

from .attention import needs_attention
from .discovery_state import (
    AttemptView,
    DiscoveryState,
    SitePage,
    Status,
    activity_rows,
    inventory,
    server_state,
    site_page,
)
from .forms import ServerForm, ServerSearchForm
from .models import Server
from .registration import (
    RemovalBlocked,
    SaveOutcome,
    active_matching_registration,
    remove_server,
    save_server,
)
from .ssh_config import load_aliases
from .trust import ConfirmationRefused, confirm_host, pending_challenge


def _is_fragment_request(request: HttpRequest) -> bool:
    # History restores and body-targeted requests need the complete page.
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def _save(form: ServerForm, request: HttpRequest) -> SaveOutcome | None:
    if not isinstance(request.user, User):
        raise Http404
    outcome = save_server(form.save(commit=False), user=request.user)
    if outcome is SaveOutcome.TAKEN:
        existing = active_matching_registration(form.instance)
        if existing is not None:
            form.instance = existing
            return SaveOutcome.QUEUED
        form.add_error(None, "Another server was saved with this name or alias. Try again.")
    elif outcome is SaveOutcome.BUSY:
        form.add_error(
            "ssh_alias",
            "Barectl is running a remote operation, such as a connection check, with the "
            "current alias. Change it after the operation finishes.",
        )
    elif outcome is SaveOutcome.STALE:
        form.add_error(None, "The saved connection changed. Reload the form before saving.")
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
            outcome = _save(form, request)
        except Server.DoesNotExist:
            # Removed by another request after this one loaded it.
            raise Http404 from None
    if (
        request.method == "POST"
        and saved is None
        and outcome is None
        and all(
            error.code == "unique" for errors in form.errors.as_data().values() for error in errors
        )
    ):
        existing = active_matching_registration(form.instance)
        if existing is not None:
            return redirect("server_detail", pk=existing.pk)
    if outcome is not None:
        result = form.instance
        verb = "Saved" if saved else "Registered"
        endpoint = (
            "SSH alias " + result.ssh_alias if result.connection_mode == "alias" else result.address
        )
        if outcome is SaveOutcome.QUEUED:
            messages.success(
                request,
                f"{verb} {result.name} with {endpoint}. Barectl queued a connection check.",
            )
        else:
            messages.success(request, f"{verb} {result.name}.")
        return redirect("server_detail", pk=result.pk)
    context = {
        "form": form,
        "catalog": catalog,
        "server": saved,
        "title": f"Edit {saved.name}" if saved else "Add server",
        "submit_label": "Save and check",
        "alias_unavailable": saved is not None
        and saved.connection_mode == "alias"
        and saved.ssh_alias not in catalog,
    }
    return render(request, "servers/form.html", context)


Section = Literal["overview", "sites", "stack", "setup", "activity", "advanced", "settings"]
_SECTIONS: dict[Section, str] = {
    "overview": "Overview",
    "sites": "Sites",
    "stack": "Stack",
    "setup": "Setup",
    "activity": "Activity",
    "advanced": "Advanced",
    "settings": "Settings",
}

SiteSection = Literal["overview", "runtime", "activity", "advanced", "deployments", "database"]


def _discovery_section(request: HttpRequest) -> Section:
    return "advanced" if request.GET.get("section") == "advanced" else "overview"


def _discovery_context(request: HttpRequest, state: DiscoveryState) -> dict[str, object]:
    context: dict[str, object] = {
        "server": state.server,
        "state": state,
        "Status": Status,
        "host_challenge": pending_challenge(state.server),
        "attention": needs_attention(
            state.server.pk,
            state.snapshot.collected,
            can_set_up=state.can_prepare_changes and request.user.has_perms(PREPARE_PERMISSIONS),
        )
        if state.snapshot
        else (),
    }
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
        servers = servers.filter(
            Q(name__icontains=query) | Q(ssh_alias__icontains=query) | Q(address__icontains=query)
        )
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


def _overview_section(
    request: HttpRequest, state: DiscoveryState, section: Section, context: dict[str, object]
) -> None:
    if section == "overview":
        from sites.views import creation_url

        context["site_creation_url"] = creation_url(request.user, state.server.pk)


def _stack_section(
    request: HttpRequest, state: DiscoveryState, section: Section, context: dict[str, object]
) -> None:
    """The Stack section, read from the catalog lock and the last observation alone."""
    if section == "stack":
        snapshot = state.snapshot
        requested_tab = request.GET.get("tab", "web")
        stack_tab = (
            requested_tab
            if requested_tab in {"web", "services", "catalog", "php", "defaults"}
            else "web"
        )
        context["stack_tab"] = stack_tab
        standing = snapshot.collected.standing if snapshot else None
        context["foundation_web"] = (
            tuple(
                (label, value)
                for label, value in standing.evidence
                if label in {"Caddy version", "Caddy state", "Caddy configuration"}
            )
            if standing
            else ()
        )
        if snapshot and stack_tab == "web":
            context["site_files"] = site_files(snapshot.collected)
        if snapshot and stack_tab == "php":
            context["site_pools"] = site_pools(snapshot.collected)
        context["foundation_services"] = (
            tuple(
                (label, value)
                for label, value in standing.evidence
                if label in {"Caddy state", "Nix daemon", "Journal storage"}
            )
            if standing
            else ()
        )
        context["can_add_runtime"] = (
            request.user.has_perms(PREPARE_PERMISSIONS)
            and state.can_prepare_changes
            and standing is not None
            and standing.standing == Standing.TARGET_STACK
        )
        from runtimes.defaults_views import context_for_server

        context.update(context_for_server(state.server, request.user))
        context["runtime_profiles"] = snapshot.collected.runtimes if snapshot else ()
        context["php_runtimes"] = (
            tuple(row for row in snapshot.collected.runtimes if row.entry.startswith("php"))
            if snapshot
            else ()
        )
        context["runtime_warning"] = (
            snapshot.collected.runtime_warning if snapshot else "Run discovery to list runtimes."
        )
        context["runtime_catalog"] = shown_catalog(
            checked=snapshot is not None,
            machine=snapshot.collected.architecture.value if snapshot is not None else None,
        )


def server_page(
    request: HttpRequest,
    pk: int,
    section: Section,
    *,
    http_site_form: HttpSiteForm | None = None,
    laravel_site_form: LaravelSiteForm | None = None,
    wordpress_site_form: WordPressSiteForm | None = None,
    status: int = 200,
) -> HttpResponse:
    """A server section's full page; the site forms keep a refused submission's input."""
    server = get_object_or_404(Server, pk=pk)
    state = server_state(server)
    context = _discovery_context(request, state)
    context.update(history=state.history, section=section, section_title=_SECTIONS[section])
    if section == "sites" and not request.user.has_perm(VIEW_SITES):
        raise PermissionDenied
    _overview_section(request, state, section, context)
    _stack_section(request, state, section, context)
    if section == "settings":
        from databases import engine as database_engine
        from databases.presentation import panel

        context["database_panel"] = (
            panel(state.snapshot.collected) if state.snapshot is not None else None
        )
        context["database_can_prepare"] = state.can_prepare_changes and request.user.has_perms(
            PREPARE_PERMISSIONS
        )
        context["database_install_kind"] = database_engine.SLUG
        context["database_remove_kind"] = database_engine.REMOVE_SLUG
    if section == "activity":
        context.update(attempts=list(state.history))
    if section == "setup":
        context["can_prepare_foundation"] = state.can_prepare_changes and request.user.has_perms(
            PREPARE_PERMISSIONS
        )
        context["foundation_journey"] = foundation_setup.project(state)
    standing = state.snapshot.collected.standing if state.snapshot else None
    target_host = (
        standing is not None and standing.standing != Standing.NOT_MANAGEABLE
    ) or http_site_form is not None
    context["target_host"] = target_host
    if section == "sites" and target_host:
        from sites.views import http_site_context, laravel_site_context, wordpress_site_context

        context.update(http_site_context(server, http_site_form))
        context.update(laravel_site_context(server, laravel_site_form))
        context.update(wordpress_site_context(server, wordpress_site_form))
        context["http_site_permission"] = request.user.has_perms(PREPARE_PERMISSIONS)
    return render(request, "servers/detail.html", context, status=status)


@never_cache
@require_GET
@login_required
@permission_required(("servers.view_server", VIEW_SITES), raise_exception=True)
def site_detail(
    request: HttpRequest, pk: int, identifier: str, section: SiteSection = "overview"
) -> HttpResponse:
    return site_page_response(request, pk, identifier, section)


def _target_site_context(
    page: SitePage, state: DiscoveryState, section: SiteSection, context: dict[str, object]
) -> None:
    site = page.site
    target = site is not None and site.file.startswith("/etc/caddy/sites/")
    if not target:
        if section == "runtime":
            raise Http404
        return
    if section not in {"overview", "runtime", "activity", "deployments", "database"}:
        raise Http404
    snapshot = state.snapshot
    if snapshot is None or site is None:
        return
    context["site_runtime"] = next(
        (row for row in snapshot.collected.runtimes if row.entry == site.php_version), None
    )
    context["runtime_site_count"] = sum(
        row.php_version == site.php_version and row.file.startswith("/etc/caddy/sites/")
        for row in snapshot.collected.sites.value
    )
    context["has_releases"] = any(
        release.identifier == site.identifier for release in snapshot.collected.releases.value
    )


def _site_activity_context(
    request: HttpRequest,
    server: Server,
    identifier: str,
    section: SiteSection,
    target_site: bool,
    context: dict[str, object],
) -> None:
    if section != "activity" or not target_site:
        return
    from operations.models import VIEW_CHANGES
    from operations.presentation import change_view
    from operations.services import read_changes

    permitted = request.user.has_perm(VIEW_CHANGES)
    context["target_activity_allowed"] = permitted
    context["target_activity"] = (
        [
            change_view(row)
            for row in read_changes(server).rows
            if row.preparation.inputs.get("identifier") == identifier
        ]
        if permitted
        else []
    )


def site_page_response(
    request: HttpRequest,
    pk: int,
    identifier: str,
    section: SiteSection,
    *,
    status: int = 200,
) -> HttpResponse:
    """A site section's full page."""
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
    target_site = page.site is not None and page.site.file.startswith("/etc/caddy/sites/")
    context["target_site"] = target_site
    _target_site_context(page, state, section, context)
    if target_site and section == "runtime":
        from sites.node_views import context_for_site
        from sites.php_views import context_for_site as php_context_for_site
        from sites.readiness_views import context_for_site as readiness_context_for_site

        context.update(context_for_site(server, identifier, request.user))
        context.update(php_context_for_site(server, identifier, request.user))
        context.update(
            readiness_context_for_site(
                server,
                identifier,
                request.user,
                has_releases=bool(context.get("has_releases")),
            )
        )
        context["blocking"] = blocking_operation(state.other_operation)
    _site_activity_context(request, server, identifier, section, target_site, context)
    if target_site and section == "database":
        from databases.site_views import context_for_site as database_context_for_site

        context.update(database_context_for_site(server, identifier, request.user))
    if target_site and section == "deployments":
        from discovery.presentation import present_releases
        from sites.deploy_views import deploy_context

        context.update(deploy_context(server, identifier, request.user))
        context["releases"] = (
            present_releases(state.snapshot.collected.releases, identifier)
            if state.snapshot is not None
            else ()
        )
        context["blocking"] = blocking_operation(state.other_operation)
    return render(request, "sites/detail.html", context, status=status)


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def activity(request: HttpRequest) -> HttpResponse:
    rows: list[AttemptView] = list(activity_rows())
    return render(request, "servers/activity.html", {"attempts": rows})


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
    if not isinstance(request.user, User):
        raise Http404
    try:
        request_discovery(server, user=request.user)
    except Server.DoesNotExist:
        # Removed by another request after this one loaded it.
        raise Http404 from None
    except OperationRefused:
        messages.error(request, "The connection changed. Reload and request a new check.")
        return redirect("server_detail", pk=pk)
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
    stale_registration = False
    current_revision = server.registration_revision
    # The confirming button submits this field; any other request only shows the page.
    if request.method == "POST" and request.POST.get("confirm") == "remove":
        name = server.name
        try:
            expected = request.POST.get("expected_revision")
            if expected is not None:
                try:
                    server.registration_revision = int(expected)
                except ValueError:
                    stale_registration = True
                    raise RemovalBlocked from None
                stale_registration = server.registration_revision != current_revision
            elif server.registration_revision > 0:
                stale_registration = True
                raise RemovalBlocked
            remove_server(server)
        except Server.DoesNotExist:
            raise Http404 from None
        except RemovalBlocked:
            refused = True
            server.registration_revision = current_revision
        else:
            messages.success(request, f"Removed {name} and its local history from Barectl.")
            return redirect("servers")
    context = {
        "server": server,
        "recorded": recorded_discovery(server),
        "refused": refused,
        "stale_registration": stale_registration,
    }
    # A refused removal conflicts with discovery, even one that has finished since.
    return render(request, "servers/remove.html", context, status=409 if refused else 200)


@never_cache
@require_POST
@login_required
@permission_required(
    ("servers.view_server", "servers.change_server", "discovery.add_discoveryattempt"),
    raise_exception=True,
)
def server_confirm_host(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    if not isinstance(request.user, User):
        raise Http404
    try:
        attempt_id = int(request.POST.get("attempt", ""))
        revision = int(request.POST.get("revision", ""))
    except ValueError:
        return HttpResponse("Invalid host key confirmation.", status=400)
    try:
        confirm_host(
            server,
            attempt_id=attempt_id,
            revision=revision,
            fingerprint=request.POST.get("fingerprint", ""),
            user=request.user,
        )
    except ConfirmationRefused as refusal:
        messages.error(request, str(refusal))
        return server_page(request, pk, "overview", status=409)
    messages.success(request, "Host fingerprint confirmed. Barectl queued a connection check.")
    return redirect("server_detail", pk=pk)
