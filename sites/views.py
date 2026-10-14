"""docs/sites.md#preparing-a-site-plan"""

from collections.abc import Mapping
from typing import Literal

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from bootstrap.php_supply import ELIGIBLE_BRANCHES, supported
from bootstrap.services import ServerPlans
from bootstrap.standing import Standing
from bootstrap.views import plans_token
from dashboard.middleware import is_htmx_request
from discovery.models import WebStackComponent
from discovery.presentation import VIEW_SITES, present_sites
from operations import services as change_services
from operations.consent import PREPARE_PERMISSIONS
from servers.discovery_state import DiscoveryState, server_state, site_page
from servers.models import Server

from .forms import HttpSiteForm, SiteForm
from .handler import AUTHORITY
from .services import read_site_plans, request_site_preparation

BUSY = (
    "Barectl is running another remote operation for this server. Prepare the site plan after "
    "it finishes."
)
INVALID = "Correct the site identifier or names."


def form_for_server(
    server: Server,
    data: Mapping[str, str] | None = None,
    *,
    initial: dict[str, str] | None = None,
    auto_id: str = "id_site_%s",
) -> SiteForm:
    state = server_state(server)
    snapshot = state.snapshot
    versions: tuple[str, ...] = ()
    if snapshot is not None and state.snapshot_notice is None:
        component = next(
            (
                item
                for item in snapshot.collected.components
                if item.component == WebStackComponent.PHP_FPM
            ),
            None,
        )
        if component is not None and component.package.observed:
            names = {package.name for package in component.package.value}
            versions = tuple(
                branch
                for branch in ELIGIBLE_BRANCHES
                if f"php{branch}-fpm" in names and supported(branch, timezone.now().date())
            )
    return SiteForm(data, initial=initial, auto_id=auto_id, php_versions=versions)


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def creation_section(user: User | AnonymousUser) -> Literal["sites", "advanced"]:
    """Creation begins from Sites; an account that may not view site observations keeps the
    Advanced copy of the form."""
    return "sites" if user.has_perm(VIEW_SITES) else "advanced"


def creation_url(user: User | AnonymousUser, pk: int) -> str:
    return f"{reverse(f'server_{creation_section(user)}', args=[pk])}#site-plans"


def site_context(
    server: Server, plans: ServerPlans, form: SiteForm | None = None
) -> dict[str, object]:
    """What the server page's site plan section needs; the server page includes it too."""
    state = server_state(server)
    snapshot = state.snapshot
    return {
        "server": server,
        "site_plans": plans,
        "site_latest": plans.latest,
        "site_form": form or form_for_server(server),
        "site_php_observed_at": snapshot.collected_at if snapshot is not None else None,
        "site_token": plans_token(plans),
    }


def _fragment(
    request: HttpRequest,
    server: Server,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    form: SiteForm | None = None,
    status: int = 200,
) -> HttpResponse:
    plans = read_site_plans(server)
    context = site_context(server, plans, form)
    context.update(site_focus=focus, site_problem=problem)
    latest = plans.latest
    if latest is not None and (focus or (shown is not None and shown != context["site_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "sites/_sites_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def server_site_plans(request: HttpRequest, pk: int) -> HttpResponse:
    """The site plan section, polled while a remote operation is active for the server."""
    server = get_object_or_404(Server, pk=pk)
    if not _is_fragment_request(request):
        from servers.views import server_detail

        return server_detail(request, pk, section="sites")
    if not request.user.has_perms(AUTHORITY.view):
        raise PermissionDenied
    return _fragment(request, server, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(AUTHORITY.prepare, raise_exception=True)
def server_site_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    form = form_for_server(server, request.POST)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, form=form, status=422)
        from servers.views import server_page

        messages.error(request, INVALID)
        return server_page(request, pk, creation_section(user), site_form=form, status=422)
    try:
        page = site_page(server_state(server), form.cleaned_data["identifier"])
        revision = page.site.convention_revision if page.site is not None and page.current else 4
        queued = request_site_preparation(
            server,
            user,
            form.cleaned_data["identifier"],
            form.cleaned_data["names"],
            php_version=form.cleaned_data["php_version"],
            convention_revision=revision,
        )
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request, f"Barectl queued a site plan preparation for {server.name}. Nothing changes."
        )
    return redirect(creation_url(user, pk))


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
    return {
        "http_site_form": form if form is not None else HttpSiteForm(php_versions=versions),
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
            },
        )
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
