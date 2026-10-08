"""docs/wordpress.md#wp-cli-setup and docs/wordpress.md#php-runtime"""

from functools import partial

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from bootstrap.services import ServerPlans
from bootstrap.views import plans_token
from dashboard.middleware import is_htmx_request
from servers.discovery_state import SitePage
from servers.models import Server
from servers.site_access import shown_site, stale_refusal

from .handler import AUTHORITY
from .models import PlanWpcliTool
from .services import (
    read_site_runtime,
    read_wordpress_plans,
    request_runtime_preparation,
    request_setup_preparation,
)

BUSY = "Barectl is running another remote operation for this server. Try again after it finishes."


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def wordpress_context(server: Server, plans: ServerPlans) -> dict[str, object]:
    """What the server page's WordPress section needs; the server page includes it too."""
    return {
        "server": server,
        "wpcli_plans": plans,
        "wpcli_latest": plans.latest,
        "wpcli_token": plans_token(plans),
    }


def _fragment(
    request: HttpRequest,
    server: Server,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    status: int = 200,
) -> HttpResponse:
    plans = read_wordpress_plans(server)
    context = wordpress_context(server, plans)
    context.update(wpcli_focus=focus, wpcli_problem=problem)
    latest = plans.latest
    if problem:
        context["announcement"] = problem
    elif latest is not None and (focus or (shown is not None and shown != context["wpcli_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "wordpress/_wordpress_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required(("servers.view_server", *AUTHORITY.view), raise_exception=True)
def server_wordpress_plans(request: HttpRequest, pk: int) -> HttpResponse:
    """The WordPress section, polled while a remote operation is active."""
    server = get_object_or_404(Server, pk=pk)
    if not _is_fragment_request(request):
        return redirect("server_advanced", pk=pk)
    return _fragment(request, server, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(("servers.view_server", *AUTHORITY.prepare), raise_exception=True)
def server_wpcli_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    try:
        queued = request_setup_preparation(server, user)
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a WP-CLI setup plan preparation for {server.name}. Nothing changes.",
        )
    return redirect(f"{reverse('server_advanced', args=[pk])}#wordpress-plans")


# The site's WordPress section: the PHP runtime card (docs/wordpress.md#php-runtime) -----------


def site_runtime_context(server: Server, identifier: str, plans: ServerPlans) -> dict[str, object]:
    """What the selected site's WordPress runtime card needs."""
    tool = (
        PlanWpcliTool.objects.filter(plan__preparation__server=server)
        .order_by("-plan__collected_at", "-pk")
        .select_related("plan")
        .first()
    )
    return {
        "server": server,
        "identifier": identifier,
        "wprt_plans": plans,
        "wprt_latest": plans.latest,
        "wprt_token": plans_token(plans),
        "wprt_tool": tool,
    }


def _site_runtime_fragment(
    request: HttpRequest,
    server: Server,
    page: SitePage,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    status: int = 200,
) -> HttpResponse:
    plans = read_site_runtime(server, page.identifier)
    context = site_runtime_context(server, page.identifier, plans)
    context.update(site=page.site, site_page=page, wprt_focus=focus, wprt_problem=problem)
    latest = plans.latest
    if problem:
        context["announcement"] = problem
    elif latest is not None and (focus or (shown is not None and shown != context["wprt_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "wordpress/_site_runtime_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *AUTHORITY.view),
    raise_exception=True,
)
def site_runtime_plans(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """The selected site's runtime card, polled while a remote operation is active."""
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    if not _is_fragment_request(request):
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    return _site_runtime_fragment(request, server, page, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *AUTHORITY.prepare),
    raise_exception=True,
)
def site_runtime_prepare(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    target = f"{reverse('site_wordpress', args=[pk, identifier])}#site-wordpress-runtime"
    refused = stale_refusal(
        request,
        page,
        partial=_is_fragment_request(request),
        fragment=partial(_site_runtime_fragment, request, server, page, focus=True),
        target=target,
    )
    if refused is not None:
        return refused
    try:
        queued = request_runtime_preparation(server, user, identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _site_runtime_fragment(
            request, server, page, focus=True, problem="" if queued else BUSY
        )
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a WordPress PHP runtime plan for site {identifier}. Nothing changes.",
        )
    return redirect(target)
