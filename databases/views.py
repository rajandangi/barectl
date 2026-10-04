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
from bootstrap.services import ServerPlans
from bootstrap.views import plans_token
from dashboard.middleware import is_htmx_request
from servers.models import Server

from . import binding
from .forms import BINDING_CHOICES, DRIVER_CHOICES, INSPECTION, BindingForm, PrepareForm
from .handler import AUTHORITY
from .services import (
    read_database_plans,
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
        "database_form": form or BindingForm(),
        "database_token": plans_token(plans),
    }


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
    form = BindingForm(request.POST)
    if action in binding.BY_ACTION and not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, form=form, status=422)
        messages.error(request, INVALID)
        return redirect(f"{reverse('server_advanced', args=[pk])}#database-plans")
    try:
        queued = _queue(server, user, action, form)
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a database plan preparation for {server.name}. Nothing changes.",
        )
    return redirect(f"{reverse('server_advanced', args=[pk])}#database-plans")
