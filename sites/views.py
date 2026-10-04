"""docs/sites.md#preparing-a-site-plan"""

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

from .forms import SiteForm
from .handler import AUTHORITY
from .services import read_site_plans, request_site_preparation

BUSY = (
    "Barectl is running another remote operation for this server. Prepare the site plan after "
    "it finishes."
)
INVALID = "Correct the site identifier or names."


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def site_context(
    server: Server, plans: ServerPlans, form: SiteForm | None = None
) -> dict[str, object]:
    """What the server page's site plan section needs; the server page includes it too."""
    return {
        "server": server,
        "site_plans": plans,
        "site_latest": plans.latest,
        "site_form": form or SiteForm(),
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
    form = SiteForm(request.POST)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, form=form, status=422)
        messages.error(request, INVALID)
        return redirect(f"{reverse('server_advanced', args=[pk])}#site-plans")
    try:
        queued = request_site_preparation(
            server, user, form.cleaned_data["identifier"], form.cleaned_data["names"]
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
    return redirect(f"{reverse('server_advanced', args=[pk])}#site-plans")
