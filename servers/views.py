from collections.abc import Iterable
from copy import copy
from typing import Literal
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.db.models import Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from bootstrap.standing import Standing
from dashboard.middleware import is_htmx_request
from discovery.presentation import VIEW_SITES, present_sites
from discovery.services import recorded_discovery, request_discovery
from operations import activity as activity_read
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from operations.models import CHANGE_SHARED, VIEW_CHANGES
from operations.presentation import blocking_operation
from runtimes.presentation import shown_catalog, shown_runtimes, shown_updates
from sites import names as site_names
from sites.forms import HttpSiteForm, LaravelSiteForm, WordPressSiteForm
from sites.recognition import site_files, site_pools

from .attention import needs_attention
from .discovery_state import (
    AttemptView,
    DiscoveryState,
    SitePage,
    Status,
    inventory,
    server_state,
    site_page,
)
from .discovery_state import (
    activity_rows as recorded_activity,
)
from .forms import ServerForm, ServerSearchForm
from .models import Server
from .page import banner, status_line
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
        "more_open": _more_options_open(form),
        "alias_unavailable": saved is not None
        and saved.connection_mode == "alias"
        and saved.ssh_alias not in catalog,
    }
    return render(request, "servers/form.html", context)


def _more_options_open(form: ServerForm) -> bool:
    """Open More options when its values differ from the common case or need fixing."""
    if form.errors.get("port") or form.errors.get("ssh_alias"):
        return True
    port = form["port"].value()
    alias = form["ssh_alias"].value()
    return (port not in (None, "", 22, "22")) or bool(alias)


Section = Literal["sites", "security", "activity", "advanced", "settings"]
_SECTIONS: dict[Section, str] = {
    "sites": "Sites",
    "security": "Security",
    "activity": "Activity",
    "advanced": "Advanced",
    "settings": "Settings",
}

SiteSection = Literal[
    "overview",
    "backups",
    "activity",
    "logs",
    "deployments",
    "database",
    "wordpress",
    "environment",
    "settings",
]


def _discovery_section(request: HttpRequest) -> Section:
    return "advanced" if request.GET.get("section") == "advanced" else "sites"


def _discovery_context(request: HttpRequest, state: DiscoveryState) -> dict[str, object]:
    attention = (
        needs_attention(
            state.server.pk,
            state.snapshot.collected,
            can_set_up=state.can_prepare_changes and request.user.has_perms(PREPARE_PERMISSIONS),
        )
        if state.snapshot
        else ()
    )
    challenge = pending_challenge(state.server)
    can_set_up = state.can_prepare_changes and request.user.has_perms(PREPARE_PERMISSIONS)
    context: dict[str, object] = {
        "server": state.server,
        "state": state,
        "Status": Status,
        "host_challenge": challenge,
        "attention": attention,
        "status_line": status_line(state),
        "banner": banner(
            state,
            host_challenge=challenge is not None,
            can_set_up=can_set_up,
            can_request_check=(
                state.can_request
                and state.alias_usable
                and request.user.has_perm("discovery.add_discoveryattempt")
            ),
            can_edit=request.user.has_perm("servers.change_server"),
            attention=attention,
        ),
    }
    if request.user.has_perm(VIEW_SITES):
        context["show_sites"] = True
        if state.snapshot is not None:
            from backups.schedule import recent_missing

            context["sites"] = present_sites(
                state.snapshot.collected.sites,
                recent_missing(state.snapshot.collected),
            )
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
def server_detail(request: HttpRequest, pk: int, section: Section = "sites") -> HttpResponse:
    return server_page(request, pk, section)


def _sites_section(
    request: HttpRequest, state: DiscoveryState, section: Section, context: dict[str, object]
) -> None:
    if section == "sites":
        from sites.views import creation_url

        context["site_creation_url"] = creation_url(request.user, state.server.pk)


def _advanced_section(
    request: HttpRequest, state: DiscoveryState, section: Section, context: dict[str, object]
) -> None:
    """Advanced holds the Stack and the stored evidence, read from the last observation."""
    if section == "advanced":
        snapshot = state.snapshot
        requested_tab = request.GET.get("tab", "web")
        stack_tab = (
            requested_tab if requested_tab in {"web", "services", "catalog", "php"} else "web"
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
        context["can_clean_up"] = (
            request.user.has_perms(PREPARE_PERMISSIONS) and state.can_prepare_changes
        )
        runtime_rows = shown_runtimes(snapshot.collected) if snapshot else ()
        runtime_updates = shown_updates(snapshot.collected, runtime_rows) if snapshot else ()
        context["runtime_profiles"] = runtime_rows
        context["php_runtimes"] = tuple(row for row in runtime_rows if row.entry.startswith("php"))
        context["runtime_updates"] = runtime_updates
        context["runtime_update_blocked"] = any(row.reason for row in runtime_updates)
        context["runtime_warning"] = (
            snapshot.collected.runtime_warning if snapshot else "Run discovery to list runtimes."
        )
        context["runtime_catalog"] = shown_catalog(
            checked=snapshot is not None,
            machine=snapshot.collected.architecture.value if snapshot is not None else None,
        )
        from security.presentation import check_reads

        security = snapshot.collected.security.value if snapshot is not None else None
        context["security_reads"] = check_reads(security)


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
    context.update(
        history=state.history,
        snapshot=state.snapshot,
        section=section,
        section_title=_SECTIONS[section],
    )
    if section == "sites" and not request.user.has_perm(VIEW_SITES):
        context["sites_forbidden"] = True
    _sites_section(request, state, section, context)
    _advanced_section(request, state, section, context)
    if section == "settings":
        from bootstrap.certificate_email_views import context_for_server
        from cache import engine as cache_engine
        from cache.presentation import panel as cache_panel
        from databases import engine as database_engine
        from databases.presentation import panel
        from runtimes.defaults_views import context_for_server as runtime_context_for_server

        context.update(context_for_server(server, request.user, state))
        context.update(runtime_context_for_server(state, request.user))
        context["database_panel"] = (
            panel(state.snapshot.collected) if state.snapshot is not None else None
        )
        context["database_can_prepare"] = state.can_prepare_changes and request.user.has_perms(
            PREPARE_PERMISSIONS
        )
        context["database_install_kind"] = database_engine.SLUG
        context["database_remove_kind"] = database_engine.REMOVE_SLUG
        context["object_cache_panel"] = (
            cache_panel(state.snapshot.collected) if state.snapshot is not None else None
        )
        context["object_cache_can_prepare"] = state.can_prepare_changes and request.user.has_perms(
            (*PREPARE_PERMISSIONS, CHANGE_SHARED)
        )
        context["object_cache_kind"] = cache_engine.SLUG
        from servers.backup_storage import context_for_server as backup_storage_context

        context.update(backup_storage_context(server, request.user, state))
    if section == "activity":
        context.update(
            _activity_context(
                request,
                server,
                "",
                attempts=state.history,
                show_servers=False,
            )
        )
    if section == "advanced":
        context["presented"] = state.presentation
    if section == "security":
        from security.presentation import present as present_security

        can_change_security = state.can_prepare_changes and request.user.has_perms(
            (*PREPARE_PERMISSIONS, CHANGE_SHARED)
        )
        context["security_checks"] = (
            present_security(
                state.snapshot.collected,
                state.snapshot.collected_at,
                advanced_url=reverse("server_advanced", args=[server.pk]),
                auto_updates_url=reverse("security_auto_updates_prepare", args=[server.pk]),
                can_change=can_change_security,
            )
            if state.snapshot is not None
            else ()
        )
    standing = state.snapshot.collected.standing if state.snapshot else None
    target_host = (
        standing is not None and standing.standing != Standing.NOT_MANAGEABLE
    ) or http_site_form is not None
    context["target_host"] = target_host
    if section == "sites" and target_host:
        from sites import continuation
        from sites.views import http_site_context, laravel_site_context, wordpress_site_context

        step = continuation.requested_step(request, server.pk)
        context.update(http_site_context(server, http_site_form, step))
        context.update(laravel_site_context(server, laravel_site_form, step))
        context.update(wordpress_site_context(server, wordpress_site_form, step))
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
        if section in ("settings", "wordpress", "environment"):
            raise Http404
        return
    if section not in {
        "overview",
        "backups",
        "activity",
        "logs",
        "deployments",
        "database",
        "wordpress",
        "environment",
        "settings",
    }:
        raise Http404
    snapshot = state.snapshot
    if snapshot is None or site is None:
        return
    observed = next(
        (row for row in snapshot.collected.sites.value if row.identifier == site.identifier),
        None,
    )
    wordpress = observed is not None and observed.application in (
        "wordpress",
        "wordpress_partial",
    )
    settings = snapshot.collected.settings if snapshot.collected.settings.observed else None
    laravel = (
        observed is not None
        and settings is not None
        and any(
            item.identifier == site.identifier and item.application == "laravel"
            for item in settings.value
        )
    )
    if section == "wordpress" and not wordpress:
        raise Http404
    if section == "environment" and not laravel:
        raise Http404
    context["has_wordpress"] = wordpress
    context["has_laravel"] = laravel
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
    context["target_activity_allowed"] = request.user.has_perm(VIEW_CHANGES)
    context.update(_activity_context(request, server, identifier, show_servers=False))


def _site_backups_context(
    server: Server,
    identifier: str,
    user: User | AnonymousUser,
    context: dict[str, object],
) -> None:
    """The Backups section from stored rows only (#396)."""
    from backups import convention as backup_convention
    from backups.presentation import BackupsView
    from backups.views import context_for_site as backups_context_for_site

    context.update(backups_context_for_site(server, identifier, user))
    from backups import schedule as backup_schedule

    backup_schedule.context_for_site(server, identifier, context)
    backups = context.get("backups")
    context["backups_repository"] = (
        backup_convention.repository(identifier)
        if isinstance(backups, BackupsView) and backups.enabled
        else ""
    )


def _site_overview_context(
    request: HttpRequest,
    server: Server,
    state: DiscoveryState,
    page: SitePage,
    identifier: str,
    context: dict[str, object],
) -> None:
    """The Overview's address and next step, from stored observations only (Phase B #446)."""
    site = page.site
    if site is None or not site.domains:
        return
    scheme = "https" if site.https else "http"
    primary = site.domains[0]
    context["site_address"] = f"{scheme}://{primary}"
    context["site_primary"] = primary
    context["site_https"] = site.https
    context["site_readiness_path"] = site.readiness
    context["site_upload_path"] = f"/var/www/{site.identifier}/current/public"
    context["site_user"] = f"s{site.identifier}"
    context["site_checked_at"] = state.snapshot.collected_at if state.snapshot else None
    from backups.views import context_for_site as backups_context_for_site

    backup_context = backups_context_for_site(server, identifier, request.user)
    context["site_reopen"] = bool(
        backup_context.get("backups") is not None
        and getattr(backup_context["backups"], "reopen", False)
    )
    context["site_reopen_can_prepare"] = backup_context.get("backups_can_reopen", False)
    context["site_reopen_restore"] = bool(
        backup_context.get("backups") is not None
        and getattr(backup_context["backups"], "restore", False)
    )
    if state.snapshot is not None and any(
        row.identifier == site.identifier for row in state.snapshot.collected.automation.value
    ):
        from automation import presentation

        context["site_schedule_lines"] = presentation.lines(
            state.snapshot.collected,
            site.identifier,
            state.snapshot.collected_at,
            presentation.paused_change(server, site.identifier),
        )
    if context.get("has_wordpress"):
        context["site_wordpress_admin"] = f"{scheme}://{primary}/wp-admin/"
    if context.get("has_laravel") and state.snapshot is not None:
        from automation import worker_presentation

        context["site_worker_lines"] = worker_presentation.lines(
            state.snapshot.collected, site.identifier, state.snapshot.collected_at
        )
    if not context.get("has_laravel"):
        return
    from discovery.presentation import present_releases
    from sites.deploy_views import deploy_context

    context.update(deploy_context(server, identifier, request.user))
    releases = (
        present_releases(state.snapshot.collected.releases, identifier)
        if state.snapshot is not None
        else ()
    )
    context["releases"] = releases
    context["site_current_release"] = next(
        (release for release in releases if release.current), None
    )
    context["blocking"] = blocking_operation(state.other_operation)


def site_page_response(  # noqa: C901 - one dispatcher for the site sections
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
    if target_site and section == "overview":
        from cache.presentation import overview_context as cache_overview_context
        from sites.php_views import context_for_site as php_overview_context

        context.update(php_overview_context(server, identifier, request.user))
        context.update(cache_overview_context(server, identifier, request.user))
    if target_site and section == "settings":
        from automation.views import context_for_site as automation_context_for_site
        from automation.worker_views import context_for_site as worker_context_for_site
        from sites.domains_views import context_for_site as domains_context_for_site
        from sites.node_views import context_for_site
        from sites.php_views import context_for_site as php_context_for_site
        from sites.pool_views import context_for_site as pool_context_for_site
        from sites.readiness_views import context_for_site as readiness_context_for_site
        from sites.remove_views import context_for_site as remove_context_for_site

        context.update(context_for_site(server, identifier, request.user))
        context.update(php_context_for_site(server, identifier, request.user))
        context.update(pool_context_for_site(server, identifier, request.user))
        context.update(
            readiness_context_for_site(
                server,
                identifier,
                request.user,
                has_releases=bool(context.get("has_releases")),
            )
        )
        context.update(domains_context_for_site(server, identifier, request.user))
        from cache.presentation import site_context as cache_context_for_site

        context.update(cache_context_for_site(server, identifier, request.user))
        context.update(remove_context_for_site(server, identifier, request.user))
        context.update(automation_context_for_site(server, identifier, request.user))
        context.update(worker_context_for_site(server, identifier, request.user))
        context["blocking"] = blocking_operation(state.other_operation)
    _site_activity_context(request, server, identifier, section, target_site, context)
    if target_site and section == "database":
        from databases.site_views import context_for_site as database_context_for_site

        context.update(database_context_for_site(server, identifier, request.user))
    if target_site and section == "backups":
        _site_backups_context(server, identifier, request.user, context)
    if target_site and section == "overview":
        _site_overview_context(request, server, state, page, identifier, context)
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
    if target_site and section == "wordpress":
        from wordpress.settings_views import context_for_site as wordpress_settings_context
        from wordpress.views import context_for_site as wordpress_context_for_site

        context.update(wordpress_context_for_site(server, identifier, request.user))
        context.update(wordpress_settings_context(server, identifier, request.user))
        context["blocking"] = blocking_operation(state.other_operation)
    if target_site and section == "environment":
        from laravel.settings_views import context_for_site as environment_context_for_site

        context.update(environment_context_for_site(server, identifier, request.user))
        context["blocking"] = blocking_operation(state.other_operation)
    if section == "logs":
        from logs.services import context_for_site as logs_context_for_site

        context.update(
            logs_context_for_site(
                server,
                identifier,
                request.user,
                selected=request.GET.get("log", ""),
                live=request.GET.get("live") == "1",
            )
        )
    return render(request, "sites/detail.html", context, status=status)


def _activity_rows_url(server: Server | None, site: str) -> str:
    query = {}
    if server is not None:
        query["server"] = str(server.pk)
    if site:
        query["site"] = site
    url = reverse("activity_rows")
    return f"{url}?{urlencode(query)}" if query else url


def _activity_context(
    request: HttpRequest,
    server: Server | None,
    site: str,
    *,
    attempts: Iterable[AttemptView] | None = None,
    show_servers: bool,
    shown: str | None = None,
) -> dict[str, object]:
    """The Activity list for one scope, read from stored rows only."""
    if site:
        # A check belongs to its whole server, never to a site.
        attempts = ()
    elif attempts is None:
        attempts = recorded_activity() if server is None else server_state(server).history
    rows = activity_read.check_rows(attempts)
    if request.user.has_perm(VIEW_CHANGES):
        rows += activity_read.change_rows(server)
    listed = activity_read.Activity(activity_read.newest_first(rows, site=site))
    context: dict[str, object] = {
        "activity": listed,
        "rows_url": _activity_rows_url(server, site),
        "show_servers": show_servers,
        "sites": sorted({row.site for row in rows if row.site}),
        "site_filter": site,
    }
    if shown is not None and shown != listed.token:
        context["announcement"] = "Activity updated."
    return context


def _activity_scope(request: HttpRequest) -> tuple[Server | None, str]:
    """The server and site an Activity list is narrowed to, from its query string."""
    site = request.GET.get("site", "").strip()
    if not site_names.valid_identifier(site):
        site = ""
    raw_server = request.GET.get("server", "")
    server = Server.objects.filter(pk=int(raw_server)).first() if raw_server.isdigit() else None
    return server, site


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def activity(request: HttpRequest) -> HttpResponse:
    server, site = _activity_scope(request)
    context = _activity_context(request, server, site, show_servers=server is None)
    context.update(
        servers=list(Server.objects.order_by("name")),
        selected_server=server,
    )
    return render(request, "servers/activity.html", context)


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def activity_rows(request: HttpRequest) -> HttpResponse:
    """The Activity list, polled while a check or change is active."""
    if not _is_fragment_request(request):
        query = request.GET.copy()
        query.pop("shown", None)
        url = reverse("activity")
        return redirect(f"{url}?{query.urlencode()}" if query else url)
    server, site = _activity_scope(request)
    context = _activity_context(
        request,
        server,
        site,
        show_servers=server is None,
        shown=request.GET.get("shown", ""),
    )
    response = render(request, "servers/_activity_rows.html", context)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def server_status(request: HttpRequest, pk: int) -> HttpResponse:
    """The server page's status line, polled while a connection check runs."""
    server = get_object_or_404(Server, pk=pk)
    if not _is_fragment_request(request):
        return redirect("server_detail", pk=pk)
    state = server_state(server)
    context = _discovery_context(request, state)
    if state.changed_since(request.GET.get("shown")):
        context["announcement"] = state.announcement
    return render(request, "servers/_status_update.html", context)


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
        return server_page(request, pk, "settings", status=409)
    messages.success(request, "Host fingerprint confirmed. Barectl queued a connection check.")
    return redirect("server_detail", pk=pk)
