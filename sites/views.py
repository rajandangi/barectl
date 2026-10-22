"""docs/sites.md#creating-a-site"""

from typing import Literal

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from bootstrap.standing import Standing
from dashboard.middleware import is_htmx_request
from discovery.presentation import VIEW_SITES, present_sites
from operations import services as change_services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server

from .forms import HttpSiteForm, LaravelSiteForm, WordPressSiteForm

BUSY = (
    "Barectl is running another remote operation for this server. Prepare the site plan after "
    "it finishes."
)


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def creation_section(user: User | AnonymousUser) -> Literal["sites", "advanced"]:
    """Creation begins from Sites; an account that may not view site observations keeps the
    Advanced copy of the form."""
    return "sites" if user.has_perm(VIEW_SITES) else "advanced"


def creation_url(user: User | AnonymousUser, pk: int) -> str:
    return f"{reverse(f'server_{creation_section(user)}', args=[pk])}#site-plans"


def http_site_versions(state: DiscoveryState) -> tuple[str, ...]:
    snapshot = state.snapshot
    return (
        tuple(
            row.entry
            for row in snapshot.collected.runtimes
            if row.entry in {"php84", "php85"} and row.manageable and row.master_state == "active"
        )
        if snapshot is not None and state.snapshot_notice is None
        else ()
    )


def http_site_context(server: Server, form: HttpSiteForm | None = None) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    versions = http_site_versions(state)
    standing = snapshot.collected.standing if snapshot is not None else None
    defaults = snapshot.collected.runtime_defaults if snapshot is not None else None
    initial = (
        {"php_version": defaults.php}
        if defaults is not None and not defaults.php_problem and defaults.php in versions
        else None
    )
    return {
        "http_site_form": form
        if form is not None
        else HttpSiteForm(php_versions=versions, initial=initial),
        "http_site_versions": versions,
        "http_site_observed_at": snapshot.collected_at if snapshot is not None else None,
        "http_site_can_prepare": (
            standing is not None
            and standing.standing == Standing.TARGET_STACK
            and state.can_prepare_changes
            and not change_services.read_changes(server).polling
            and bool(versions)
        ),
    }


def laravel_site_context(server: Server, form: LaravelSiteForm | None = None) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    versions = http_site_versions(state)
    standing = snapshot.collected.standing if snapshot is not None else None
    defaults = snapshot.collected.runtime_defaults if snapshot is not None else None
    initial = (
        {"php_version": defaults.php}
        if defaults is not None and not defaults.php_problem and defaults.php in versions
        else None
    )
    return {
        "laravel_site_form": form
        if form is not None
        else LaravelSiteForm(php_versions=versions, initial=initial),
        "laravel_site_versions": versions,
        "laravel_site_observed_at": snapshot.collected_at if snapshot is not None else None,
        "laravel_site_can_prepare": (
            standing is not None
            and standing.standing == Standing.TARGET_STACK
            and state.can_prepare_changes
            and not change_services.read_changes(server).polling
            and bool(versions)
        ),
    }


def wordpress_site_context(
    server: Server, form: WordPressSiteForm | None = None
) -> dict[str, object]:
    from databases import observation as database_observation

    state = server_state(server)
    snapshot = state.snapshot
    versions = http_site_versions(state)
    standing = snapshot.collected.standing if snapshot is not None else None
    defaults = snapshot.collected.runtime_defaults if snapshot is not None else None
    installed = database_observation.installed_engines(snapshot.collected) if snapshot else ()
    engine = installed[0].engine if len(installed) == 1 else ""
    reason = ""
    if snapshot is not None and len(installed) > 1:
        reason = "WordPress needs one database engine; this server runs more than one."
    elif engine == database_observation.POSTGRESQL:
        reason = "WordPress needs MariaDB. This server runs PostgreSQL."
    elif not engine:
        reason = "WordPress needs MariaDB. Install a database engine from Server Settings first."
    elif not installed[0].managed:
        reason = f"{installed[0].label} is Outside supported settings."
    initial = (
        {"php_version": defaults.php}
        if defaults is not None and not defaults.php_problem and defaults.php in versions
        else None
    )
    return {
        "wordpress_site_form": form
        if form is not None
        else WordPressSiteForm(php_versions=versions, initial=initial),
        "wordpress_site_versions": versions,
        "wordpress_site_observed_at": snapshot.collected_at if snapshot is not None else None,
        "wordpress_site_reason": reason,
        "wordpress_site_can_prepare": (
            standing is not None
            and standing.standing == Standing.TARGET_STACK
            and state.can_prepare_changes
            and not change_services.read_changes(server).polling
            and bool(versions)
            and not reason
        ),
    }


def _stale_wordpress_site(request: HttpRequest, pk: int, form: WordPressSiteForm) -> HttpResponse:
    problem = (
        "The server connection changed. Reload this page and run discovery before "
        "preparing a fresh WordPress site review. Nothing was queued."
    )
    retained = WordPressSiteForm(
        {
            "identifier": form.cleaned_data["identifier"],
            "names": " ".join(form.cleaned_data["names"]),
            "title": form.cleaned_data["title"],
            "admin_username": form.cleaned_data["admin_username"],
            "admin_email": form.cleaned_data["admin_email"],
            "php_version": form.cleaned_data["php_version"],
            "http_only": form.cleaned_data["http_only"],
        },
        php_versions=(form.cleaned_data["php_version"],),
    )
    if _is_fragment_request(request):
        fresh = get_object_or_404(Server, pk=pk)
        response = render(
            request,
            "sites/_wordpress_create.html",
            {
                "server": fresh,
                **wordpress_site_context(fresh, retained),
                "wordpress_site_focus": True,
                "wordpress_site_problem": problem,
            },
            status=409,
        )
        patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
        return response
    from servers.views import server_page

    messages.error(request, problem)
    return server_page(request, pk, "sites", wordpress_site_form=retained, status=409)


def _stale_laravel_site(request: HttpRequest, pk: int, form: LaravelSiteForm) -> HttpResponse:
    problem = (
        "The server connection changed. Reload this page and run discovery before "
        "preparing a fresh Laravel site review. Nothing was queued."
    )
    retained = LaravelSiteForm(
        {
            "identifier": form.cleaned_data["identifier"],
            "names": " ".join(form.cleaned_data["names"]),
            "repository": form.cleaned_data["repository"],
            "branch": form.cleaned_data["branch"],
            "php_version": form.cleaned_data["php_version"],
            "fingerprint": form.cleaned_data["fingerprint"],
            "http_only": form.cleaned_data["http_only"],
        },
        php_versions=(form.cleaned_data["php_version"],),
    )
    if _is_fragment_request(request):
        fresh = get_object_or_404(Server, pk=pk)
        response = render(
            request,
            "sites/_laravel_create.html",
            {
                "server": fresh,
                **laravel_site_context(fresh, retained),
                "laravel_site_focus": True,
                "laravel_site_problem": problem,
            },
            status=409,
        )
        patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
        return response
    from servers.views import server_page

    messages.error(request, problem)
    return server_page(request, pk, "sites", laravel_site_form=retained, status=409)


def _stale_http_site(request: HttpRequest, pk: int, form: HttpSiteForm) -> HttpResponse:
    problem = (
        "The server connection changed. Reload this page and run discovery before "
        "preparing a fresh site review. Nothing was queued."
    )
    retained = HttpSiteForm(
        {
            "identifier": form.cleaned_data["identifier"],
            "names": " ".join(form.cleaned_data["names"]),
            "php_version": form.cleaned_data["php_version"],
            "http_only": form.cleaned_data["http_only"],
        },
        php_versions=(form.cleaned_data["php_version"],),
    )
    if _is_fragment_request(request):
        fresh = get_object_or_404(Server, pk=pk)
        response = render(
            request,
            "sites/_http_create.html",
            {
                "server": fresh,
                **http_site_context(fresh, retained),
                "http_site_focus": True,
                "http_site_problem": problem,
            },
            status=409,
        )
        patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
        return response
    from servers.views import server_page

    messages.error(request, problem)
    return server_page(request, pk, "sites", http_site_form=retained, status=409)


@never_cache
@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def server_http_site_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    context = http_site_context(server)
    form = HttpSiteForm(request.POST, php_versions=http_site_versions(server_state(server)))
    if not form.is_valid():
        from servers.views import server_page

        if _is_fragment_request(request):
            response = render(
                request,
                "sites/_http_create.html",
                {"server": server, **http_site_context(server, form), "http_site_focus": True},
                status=422,
            )
            patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
            return response
        return server_page(request, pk, "sites", http_site_form=form, status=422)
    if not context["http_site_can_prepare"]:
        messages.warning(
            request, "Run discovery and resolve the server's findings before creating a site."
        )
        return redirect("server_sites", pk=pk)
    try:
        preparation = change_services.request_prepare(
            server,
            user,
            "create_http_site",
            inputs={
                "version": 1,
                "identifier": form.cleaned_data["identifier"],
                "names": list(form.cleaned_data["names"]),
                "selection": form.cleaned_data["php_version"],
                "https": not form.cleaned_data["http_only"],
            },
        )
    except OperationRefused:
        return _stale_http_site(request, pk, form)
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(
            request, "This site request is unavailable. Run discovery and prepare a new review."
        )
        return redirect("server_sites", pk=pk)
    if preparation is None:
        messages.warning(request, BUSY)
        return redirect("server_sites", pk=pk)
    destination = reverse("change_detail", args=[preparation.pk])
    if _is_fragment_request(request):
        return HttpResponse(headers={"HX-Redirect": destination})
    return redirect(destination)


LARAVEL_CREATE_SLUG = "create_laravel_site"


@never_cache
@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def server_laravel_site_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    context = laravel_site_context(server)
    form = LaravelSiteForm(request.POST, php_versions=http_site_versions(server_state(server)))
    if not form.is_valid():
        from servers.views import server_page

        if _is_fragment_request(request):
            response = render(
                request,
                "sites/_laravel_create.html",
                {
                    "server": server,
                    **laravel_site_context(server, form),
                    "laravel_site_focus": True,
                },
                status=422,
            )
            patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
            return response
        return server_page(request, pk, "sites", laravel_site_form=form, status=422)
    if not context["laravel_site_can_prepare"]:
        messages.warning(
            request, "Run discovery and resolve the server's findings before creating a site."
        )
        return redirect("server_sites", pk=pk)
    try:
        preparation = change_services.request_prepare(
            server,
            user,
            LARAVEL_CREATE_SLUG,
            inputs={
                "version": 1,
                "identifier": form.cleaned_data["identifier"],
                "names": list(form.cleaned_data["names"]),
                "selection": form.cleaned_data["php_version"],
                "https": not form.cleaned_data["http_only"],
                "repository": form.cleaned_data["repository"],
                "branch": form.cleaned_data["branch"],
                "fingerprint": form.cleaned_data["fingerprint"],
            },
        )
    except OperationRefused:
        return _stale_laravel_site(request, pk, form)
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(
            request, "This site request is unavailable. Run discovery and prepare a new review."
        )
        return redirect("server_sites", pk=pk)
    if preparation is None:
        messages.warning(request, BUSY)
        return redirect("server_sites", pk=pk)
    destination = reverse("change_detail", args=[preparation.pk])
    if _is_fragment_request(request):
        return HttpResponse(headers={"HX-Redirect": destination})
    return redirect(destination)


WORDPRESS_CREATE_SLUG = "create_wordpress_site"


@never_cache
@require_POST
@login_required
@permission_required(
    (*PREPARE_PERMISSIONS, VIEW_SITES, "operations.manage_secrets"), raise_exception=True
)
def server_wordpress_site_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    context = wordpress_site_context(server)
    form = WordPressSiteForm(request.POST, php_versions=http_site_versions(server_state(server)))
    if not form.is_valid():
        from servers.views import server_page

        if _is_fragment_request(request):
            response = render(
                request,
                "sites/_wordpress_create.html",
                {
                    "server": server,
                    **wordpress_site_context(server, form),
                    "wordpress_site_focus": True,
                },
                status=422,
            )
            patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
            return response
        return server_page(request, pk, "sites", wordpress_site_form=form, status=422)
    if not context["wordpress_site_can_prepare"]:
        messages.warning(
            request,
            str(context["wordpress_site_reason"])
            or "Run discovery and resolve the server's findings before creating a site.",
        )
        return redirect("server_sites", pk=pk)
    try:
        preparation = change_services.request_prepare(
            server,
            user,
            WORDPRESS_CREATE_SLUG,
            inputs={
                "version": 1,
                "identifier": form.cleaned_data["identifier"],
                "names": list(form.cleaned_data["names"]),
                "selection": form.cleaned_data["php_version"],
                "https": not form.cleaned_data["http_only"],
                "title": form.cleaned_data["title"],
                "admin_username": form.cleaned_data["admin_username"],
                "admin_email": form.cleaned_data["admin_email"],
            },
        )
    except OperationRefused:
        return _stale_wordpress_site(request, pk, form)
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(
            request, "This site request is unavailable. Run discovery and prepare a new review."
        )
        return redirect("server_sites", pk=pk)
    if preparation is None:
        messages.warning(request, BUSY)
        return redirect("server_sites", pk=pk)
    destination = reverse("change_detail", args=[preparation.pk])
    if _is_fragment_request(request):
        return HttpResponse(headers={"HX-Redirect": destination})
    return redirect(destination)


@never_cache
@require_GET
@login_required
@permission_required(("servers.view_server", VIEW_SITES), raise_exception=True)
def site_list(request: HttpRequest) -> HttpResponse:
    states = [server_state(server) for server in Server.objects.order_by("name", "pk")]
    return render(
        request,
        "sites/list.html",
        {
            "rows": [
                {
                    "state": state,
                    "sites": present_sites(state.snapshot.collected.sites)
                    if state.snapshot
                    else None,
                }
                for state in states
            ],
            "can_create_sites": request.user.has_perms(PREPARE_PERMISSIONS),
        },
    )
