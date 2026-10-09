"""The site page's WordPress maintenance card (docs/wordpress.md#maintaining-wordpress)."""

from functools import partial

from django import forms
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

from bootstrap.services import ServerPlans
from bootstrap.views import plans_token
from dashboard.middleware import is_htmx_request
from servers.discovery_state import SitePage
from servers.models import Server
from servers.site_access import shown_site, stale_refusal

from .handler import MAINTAIN_AUTHORITY, RESULT_PERMISSION
from .maintenance_models import Operation
from .maintenance_presentation import latest_maintenance_result
from .services import read_site_maintenance, request_maintenance_preparation

BUSY = "Barectl is running another remote operation for this server. Try again after it finishes."


class MaintenanceForm(forms.Form):
    """Which maintenance action to review. No command, flag or target is ever supplied."""

    prefix: str | None = "maintenance"

    operation = forms.ChoiceField(
        label="Action",
        choices=Operation.choices,
        initial=Operation.REWRITE,
        widget=forms.RadioSelect(attrs={"class": "usa-radio__input"}),
        error_messages={"required": "Choose a maintenance action."},
    )


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def site_maintenance_context(
    server: Server, page: SitePage, plans: ServerPlans, user: User | AnonymousUser
) -> dict[str, object]:
    """What the selected site's maintenance card needs."""
    identifier = page.identifier
    return {
        "server": server,
        "identifier": identifier,
        "wpmx_plans": plans,
        "wpmx_latest": plans.latest,
        "wpmx_token": plans_token(plans),
        "wpmx_form": MaintenanceForm(),
        "wpmx_can_prepare": user.has_perms(MAINTAIN_AUTHORITY.prepare),
        "wpmx_can_run": user.has_perms(MAINTAIN_AUTHORITY.apply),
        "wpmx_result": (
            latest_maintenance_result(server.pk, identifier)
            if user.has_perms(RESULT_PERMISSION)
            else None
        ),
    }


def _fragment(
    request: HttpRequest,
    server: Server,
    page: SitePage,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    status: int = 200,
) -> HttpResponse:
    plans = read_site_maintenance(server, page.identifier)
    context = site_maintenance_context(server, page, plans, request.user)
    context.update(site=page.site, site_page=page, wpmx_focus=focus, wpmx_problem=problem)
    latest = plans.latest
    if problem:
        context["announcement"] = problem
    elif latest is not None and (focus or (shown is not None and shown != context["wpmx_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "wordpress/_site_maintenance_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *MAINTAIN_AUTHORITY.view),
    raise_exception=True,
)
def site_maintenance_plans(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """The selected site's maintenance card, polled while a remote operation is active."""
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    if not _is_fragment_request(request):
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    return _fragment(request, server, page, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *MAINTAIN_AUTHORITY.prepare),
    raise_exception=True,
)
def site_maintenance_prepare(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    target = f"{reverse('site_wordpress', args=[pk, identifier])}#site-wordpress-maintenance"
    refused = stale_refusal(
        request,
        page,
        partial=_is_fragment_request(request),
        fragment=partial(_fragment, request, server, page, focus=True),
        target=target,
    )
    if refused is not None:
        return refused
    form = MaintenanceForm(request.POST)
    if not form.is_valid():
        problem = "Choose one of the named maintenance actions."
        if _is_fragment_request(request):
            return _fragment(request, server, page, focus=True, problem=problem, status=422)
        messages.error(request, problem)
        return redirect(target)
    try:
        queued = request_maintenance_preparation(
            server, user, identifier, form.cleaned_data["operation"]
        )
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, page, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a WordPress maintenance review for site {identifier}. Nothing "
            "runs on the server until you apply the reviewed plan.",
        )
    return redirect(target)
