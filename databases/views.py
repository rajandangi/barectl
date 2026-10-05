"""docs/databases.md#preparing-a-database-plan"""

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

from bootstrap.models import Action, PlanPreparation
from bootstrap.profiles import DRIVER_ACTIONS
from bootstrap.services import ServerPlans, read_plans
from bootstrap.views import SiteReturn, plans_token, return_site, setup_url
from dashboard.middleware import is_htmx_request
from servers.discovery_state import STALE_SITE, SitePage, server_state, site_page
from servers.models import Server
from sites import names as site_names

from . import binding
from .forms import BINDING_CHOICES, DRIVER_CHOICES, INSPECTION, BindingForm, PrepareForm
from .handler import AUTHORITY
from .services import (
    read_database_plans,
    read_site_bindings,
    request_binding_preparation,
    request_driver_preparation,
    request_inspection,
)

BUSY = (
    "Barectl is running another remote operation for this server. Prepare the database plan "
    "after it finishes."
)
INVALID = "Correct the site identifier."


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def database_context(
    server: Server, plans: ServerPlans, form: BindingForm | None = None
) -> dict[str, object]:
    """What the server page's database plan section needs; the server page includes it too."""
    return {
        "server": server,
        "database_plans": plans,
        "database_latest": plans.latest,
        "database_drivers": DRIVER_CHOICES,
        "database_engines": BINDING_CHOICES,
        "database_inspection": INSPECTION,
        "database_form": form or BindingForm(auto_id="id_database_%s"),
        "database_token": plans_token(plans),
    }


def driver_context(server: Server, plans: ServerPlans) -> dict[str, object]:
    """What the Setup section's PHP database-driver card needs."""
    return {
        "server": server,
        "driver_plans": plans,
        "driver_latest": plans.latest,
        "driver_choices": DRIVER_CHOICES,
        "driver_token": plans_token(plans),
    }


def _driver_fragment(
    request: HttpRequest,
    server: Server,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    status: int = 200,
) -> HttpResponse:
    plans = read_plans(server, DRIVER_ACTIONS)
    context = driver_context(server, plans)
    context.update(driver_focus=focus, driver_problem=problem, site_return=return_site(request))
    latest = plans.latest
    token = context["driver_token"]
    if latest is not None and (focus or (shown is not None and shown != token)):
        context["announcement"] = latest.announcement
    response = render(request, "databases/_drivers_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


def _fragment(
    request: HttpRequest,
    server: Server,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    form: BindingForm | None = None,
    status: int = 200,
) -> HttpResponse:
    plans = read_database_plans(server)
    context = database_context(server, plans, form)
    context.update(database_focus=focus, database_problem=problem)
    latest = plans.latest
    token = context["database_token"]
    if latest is not None and (focus or (shown is not None and shown != token)):
        context["announcement"] = latest.announcement
    response = render(request, "databases/_databases_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required(AUTHORITY.view, raise_exception=True)
def server_database_plans(request: HttpRequest, pk: int) -> HttpResponse:
    """The database plan section, polled while a remote operation is active for the server."""
    server = get_object_or_404(Server, pk=pk)
    if request.GET.get("family") == "drivers":
        if not _is_fragment_request(request):
            return redirect(setup_url(request, pk))
        return _driver_fragment(request, server, shown=request.GET.get("shown"))
    if not _is_fragment_request(request):
        return redirect("server_advanced", pk=pk)
    return _fragment(request, server, shown=request.GET.get("shown"))


def _queue(server: Server, user: User, action: str, form: BindingForm) -> PlanPreparation | None:
    if action == INSPECTION:
        return request_inspection(server, user)
    spec = binding.BY_ACTION.get(action)
    if spec is not None:
        return request_binding_preparation(
            server, user, form.cleaned_data["identifier"], spec.engine
        )
    return request_driver_preparation(server, user, Action(action))


def site_binding_context(server: Server, identifier: str, plans: ServerPlans) -> dict[str, object]:
    """What the selected site's Database section needs."""
    return {
        "server": server,
        "identifier": identifier,
        "binding_plans": plans,
        "binding_latest": plans.latest,
        "binding_engines": BINDING_CHOICES,
        "binding_token": plans_token(plans),
        "setup_return_query": SiteReturn(identifier, database=True).query,
    }


def _site_binding_fragment(
    request: HttpRequest,
    server: Server,
    page: SitePage,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    status: int = 200,
) -> HttpResponse:
    identifier = page.identifier
    plans = read_site_bindings(server, identifier)
    context = site_binding_context(server, identifier, plans)
    # The fragment carries the resolved site so the one-binding guard survives polling and
    # the POST response, not just the first full page.
    context.update(
        site=page.site,
        site_stale=not page.current,
        binding_focus=focus,
        binding_problem=problem,
    )
    latest = plans.latest
    if latest is not None and (focus or (shown is not None and shown != context["binding_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "sites/_site_database_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


def _site(server: Server, identifier: str) -> SitePage:
    """The site from the server's last complete observation; refuse one it does not show."""
    if not site_names.valid_identifier(identifier):
        raise Http404
    page = site_page(server_state(server), identifier)
    if not page.found:
        raise Http404
    return page


@never_cache
@require_GET
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *AUTHORITY.view),
    raise_exception=True,
)
def site_database_plans(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """The selected site's binding section, polled while a remote operation is active."""
    server = get_object_or_404(Server, pk=pk)
    page = _site(server, identifier)
    if not _is_fragment_request(request):
        return redirect("site_database", pk=pk, identifier=identifier)
    return _site_binding_fragment(request, server, page, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *AUTHORITY.prepare),
    raise_exception=True,
)
def site_database_prepare(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    page = _site(server, identifier)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    if not page.current:
        if _is_fragment_request(request):
            return _site_binding_fragment(
                request, server, page, focus=True, problem=STALE_SITE, status=409
            )
        messages.warning(request, STALE_SITE)
        return redirect(f"{reverse('site_database', args=[pk, identifier])}#site-database-plans")
    chosen = PrepareForm(request.POST)
    spec = binding.BY_ACTION.get(chosen.cleaned_data["action"]) if chosen.is_valid() else None
    if spec is None:
        return HttpResponse("Unknown database action.", status=400)
    try:
        queued = request_binding_preparation(server, user, identifier, spec.engine)
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _site_binding_fragment(
            request, server, page, focus=True, problem="" if queued else BUSY
        )
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a {spec.engine.label} database plan for site {identifier}. "
            "Nothing changes.",
        )
    return redirect(f"{reverse('site_database', args=[pk, identifier])}#site-database-plans")


@require_POST
@login_required
@permission_required(AUTHORITY.prepare, raise_exception=True)
def server_database_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    chosen = PrepareForm(request.POST)
    if not chosen.is_valid():
        return HttpResponse("Unknown database action.", status=400)
    action: str = chosen.cleaned_data["action"]
    form = BindingForm(request.POST, auto_id="id_database_%s")
    if action in binding.BY_ACTION and not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, form=form, status=422)
        messages.error(request, INVALID)
        return redirect(f"{reverse('server_advanced', args=[pk])}#database-plans")
    try:
        queued = _queue(server, user, action, form)
    except Server.DoesNotExist:
        raise Http404 from None
    drivers = request.POST.get("family") == "drivers"
    if _is_fragment_request(request):
        if drivers:
            return _driver_fragment(request, server, focus=True, problem="" if queued else BUSY)
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a database plan preparation for {server.name}. Nothing changes.",
        )
    if drivers:
        return redirect(setup_url(request, pk, "#driver-plans"))
    return redirect(f"{reverse('server_advanced', args=[pk])}#database-plans")
