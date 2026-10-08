"""docs/wordpress.md#wp-cli-setup"""

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
from servers.models import Server

from .handler import AUTHORITY
from .services import read_wordpress_plans, request_setup_preparation

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
