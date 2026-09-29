"""docs/bootstrap.md#prerequisites"""

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

from . import actions
from .apply import (
    read_apply,
    request_apply,
    request_check,
    request_closure,
    required_permissions,
)
from .forms import AcknowledgeForm, PrepareForm
from .models import Action, ConfigurationPlan
from .presentation import ApplyView, PreparationView
from .releases import RELEASES
from .services import ServerPlans, read_plans, read_preparation, request_preparation

VIEW_PLANS = actions.BOOTSTRAP.view
PREPARE_PLANS = actions.BOOTSTRAP.prepare
BUSY = (
    "Barectl is running another remote operation for this server. Prepare the plan after it "
    "finishes."
)


def _is_fragment_request(request: HttpRequest) -> bool:
    # History restores and body-targeted requests need the complete page.
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


_PHP_VERSIONS = " and ".join(
    f"PHP {release.php} on {release.name}" for release in RELEASES.values()
)
_DESCRIPTIONS = {
    Action.NGINX: (
        "Nginx from the server's Ubuntu release, with the distribution's default site on port 80."
    ),
    Action.PHP: (
        f"FPM and CLI of the server's release's default PHP version ({_PHP_VERSIONS}), with "
        "the default pool on a local socket. Nginx is not required."
    ),
    Action.METADATA_REFRESH: (
        "Update the package indexes from the configured authenticated sources. Package "
        "plans need current indexes."
    ),
    Action.CLEAR_RESULTS: (
        "Clear the finished bootstrap runs systemd keeps on the server, after reviewing each "
        "one. Running units are never touched."
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
            if action in actions.BUILT_IN
        ],
    }


def plans_token(plans: ServerPlans) -> str:
    """The token a polling section sends back to say which state it shows."""
    latest = plans.latest
    shown = f"{latest.operation_id}.{latest.outcome.name}" if latest else ""
    run = plans.latest_apply
    if run is not None:
        shown += f"-{run.operation_id}.{run.outcome.name}"
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
    latest, run = plans.latest, plans.latest_apply
    shown_preparation, _, shown_run = (shown or "").removesuffix(".busy").partition("-")
    current_preparation, _, current_run = plans_token(plans).removesuffix(".busy").partition("-")
    if run is not None and shown is not None and shown_run != current_run:
        context["announcement"] = run.announcement
    elif latest is not None and (focus or shown_preparation != current_preparation):
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


def _may_view(request: HttpRequest, action: str) -> None:
    """docs/ssh-connections.md#site-preparation: each action's plans have their own viewers."""
    if not request.user.has_perms(actions.authority(action).view):
        raise PermissionDenied


@never_cache
@require_GET
@login_required
def plan_detail(request: HttpRequest, pk: int) -> HttpResponse:
    preparation = read_preparation(pk)
    if preparation is None:
        raise Http404
    _may_view(request, preparation.action)
    review = preparation.review
    context = {
        "preparation": preparation,
        "can_apply": review is not None
        and request.user.has_perms(required_permissions(review.plan.action))
        and _appliable(preparation),
    }
    return render(request, "bootstrap/plan.html", context)


def _appliable(preparation: PreparationView) -> bool:
    """Whether the plan page offers applying this revision now, permissions aside."""
    review = preparation.review
    return (
        review is not None
        and review.applicable
        and review.plan.eligible
        and not review.plan.no_changes
        and not review.expired
        and not review.invalidated
        and review.apply_run_id is None
    )


@require_POST
@login_required
def plan_apply(request: HttpRequest, pk: int) -> HttpResponse:
    """Queue the run of one reviewed revision; a repeated request shows the same run."""
    plan = get_object_or_404(ConfigurationPlan.objects.select_related("preparation"), pk=pk)
    _may_view(request, plan.action)
    user = request.user
    if not isinstance(user, User) or not user.has_perms(required_permissions(plan.action)):
        raise PermissionDenied
    try:
        requested = request_apply(plan, user)
    except Server.DoesNotExist:
        raise Http404 from None
    if requested.run is None:
        messages.error(request, requested.problem)
        return redirect("plan_detail", pk=pk)
    messages.success(
        request,
        f"Barectl queued plan {plan.pk} for applying. Its outcome is established from the "
        "server's native evidence.",
    )
    return redirect("apply_detail", pk=requested.run.pk)


@never_cache
@require_GET
@login_required
def apply_detail(request: HttpRequest, pk: int) -> HttpResponse:
    run = read_apply(pk)
    if run is None:
        raise Http404
    _may_view(request, run.action)
    return render(request, "bootstrap/apply.html", _apply_context(request, run))


def _apply_context(request: HttpRequest, run: ApplyView) -> dict[str, object]:
    return {
        "run": run,
        "can_acknowledge": request.user.has_perms(required_permissions(run.action)),
        "acknowledge_form": AcknowledgeForm(),
    }


@never_cache
@require_GET
@login_required
def apply_status(request: HttpRequest, pk: int) -> HttpResponse:
    """The run's status section, polled while the worker is on it or a check is pending."""
    run = read_apply(pk)
    if run is None:
        raise Http404
    _may_view(request, run.action)
    if not _is_fragment_request(request):
        return redirect("apply_detail", pk=pk)
    context = _apply_context(request, run)
    if request.GET.get("shown") != run.token:
        context["announcement"] = run.announcement
    response = render(request, "bootstrap/_apply_status_update.html", context)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@require_POST
@login_required
def apply_check(request: HttpRequest, pk: int) -> HttpResponse:
    run = read_apply(pk)
    if run is None:
        raise Http404
    _may_view(request, run.action)
    if request_check(pk):
        messages.success(request, "Barectl queued a check of this run's native outcome.")
    else:
        messages.warning(request, "Only a run whose outcome is being reconciled can be checked.")
    return redirect("apply_detail", pk=pk)


@require_POST
@login_required
def apply_acknowledge(request: HttpRequest, pk: int) -> HttpResponse:
    """docs/adr/0006-use-native-bootstrap-execution.md#unknown-outcomes"""
    run = read_apply(pk)
    if run is None:
        raise Http404
    _may_view(request, run.action)
    user = request.user
    if not isinstance(user, User) or not user.has_perms(required_permissions(run.action)):
        raise PermissionDenied
    form = AcknowledgeForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Confirm that you understand the outcome is unknown.")
    elif request_closure(pk, user):
        messages.success(
            request,
            "Barectl queued a check that closes this run as outcome unknown only if it can "
            "prove the run can no longer start or still be running.",
        )
    else:
        messages.warning(
            request,
            "Only a reconciling run whose latest check found no native record can be closed "
            "as outcome unknown.",
        )
    return redirect("apply_detail", pk=pk)
