"""Plan preparation on the server page, and one plan's review page.

Viewing plans needs ``bootstrap.view_configurationplan`` besides the inventory permission,
and preparing one needs ``bootstrap.prepare_configurationplan`` too. Requests only queue
work; the worker connects. No view offers applying a plan or clearing native results:
those permissions exist for later releases, and their controls stay hidden.
"""

from dataclasses import dataclass

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

from dashboard.middleware import is_htmx_request
from servers.models import Server

from .forms import PrepareForm
from .models import Action
from .services import ServerPlans, read_plans, read_preparation, request_preparation

VIEW_PLANS = ("servers.view_server", "bootstrap.view_configurationplan")
PREPARE_PLANS = (*VIEW_PLANS, "bootstrap.prepare_configurationplan")
BUSY = (
    "Barectl is running another remote operation for this server. Prepare the plan after it "
    "finishes."
)


def _is_fragment_request(request: HttpRequest) -> bool:
    # History restores and body-targeted requests need the complete page.
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


_DESCRIPTIONS = {
    Action.NGINX: ("Nginx from Ubuntu 24.04, with the distribution's default site on port 80."),
    Action.PHP: (
        "PHP 8.3 FPM and CLI from Ubuntu 24.04, with the default pool on a local socket. "
        "Nginx is not required."
    ),
    Action.METADATA_REFRESH: (
        "Update the package indexes from the configured authenticated sources. Package "
        "plans need current indexes."
    ),
}


@dataclass(frozen=True)
class ActionChoice:
    value: str
    label: str
    description: str
    checked: bool


def plans_context(
    server: Server, plans: ServerPlans, form: PrepareForm | None = None
) -> dict[str, object]:
    """What the server page's plan section needs; the server page includes it too."""
    chosen = form.data.get("action") if form is not None else Action.NGINX
    return {
        "server": server,
        "plans": plans,
        "latest": plans.latest,
        "prepare_form": form or PrepareForm(),
        "action_choices": [
            ActionChoice(action.value, action.label, _DESCRIPTIONS[action], action == chosen)
            for action in Action
        ],
    }


def plans_token(plans: ServerPlans) -> str:
    """The token a polling section sends back to say which state it shows."""
    latest = plans.latest
    shown = f"{latest.operation_id}.{latest.outcome.name}" if latest else ""
    return f"{shown}.busy" if plans.other_active else shown


def _fragment(
    request: HttpRequest,
    server: Server,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    form: PrepareForm | None = None,
    status: int = 200,
) -> HttpResponse:
    plans = read_plans(server)
    context = plans_context(server, plans, form)
    context.update(focus=focus, problem=problem, token=plans_token(plans))
    latest = plans.latest
    shown_part = (shown or "").removesuffix(".busy")
    if latest is not None and (focus or shown_part != plans_token(plans).removesuffix(".busy")):
        context["announcement"] = latest.announcement
    response = render(request, "bootstrap/_plans_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required(VIEW_PLANS, raise_exception=True)
def server_plans(request: HttpRequest, pk: int) -> HttpResponse:
    """The plan section, polled while a remote operation is active for the server."""
    server = get_object_or_404(Server, pk=pk)
    if not _is_fragment_request(request):
        return redirect("server_detail", pk=pk)
    return _fragment(request, server, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(PREPARE_PLANS, raise_exception=True)
def server_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    """Queue a read-only preparation of the chosen profile or action."""
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    form = PrepareForm(request.POST)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, form=form, status=422)
        messages.error(request, "Choose one of the supported profiles or actions.")
        return redirect(f"{reverse('server_detail', args=[pk])}#plans")
    try:
        queued = request_preparation(server, user, Action(form.cleaned_data["action"]))
    except Server.DoesNotExist:
        # Removed by another request after this one loaded it.
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request, f"Barectl queued a plan preparation for {server.name}. Nothing changes."
        )
    return redirect(f"{reverse('server_detail', args=[pk])}#plans")


@never_cache
@require_GET
@login_required
@permission_required(VIEW_PLANS, raise_exception=True)
def plan_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """One preparation and its plan, as the operator reviewed it or can review it now."""
    preparation = read_preparation(pk)
    if preparation is None:
        raise Http404
    return render(request, "bootstrap/plan.html", {"preparation": preparation})
