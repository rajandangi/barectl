"""The site page's WordPress inspection card (docs/wordpress.md#inspecting-wordpress)."""

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

from .handler import INSPECT_AUTHORITY, RESULT_PERMISSION
from .inspection_models import Operation
from .inspection_presentation import latest_result
from .services import read_site_inspection, request_inspection_preparation

BUSY = "Barectl is running another remote operation for this server. Try again after it finishes."


class InspectionForm(forms.Form):
    """Which diagnostic to review. No command, flag or target is ever supplied."""

    prefix: str | None = "inspection"

    operation = forms.ChoiceField(
        label="Diagnostic",
        choices=Operation.choices,
        initial=Operation.INSPECT,
        widget=forms.RadioSelect(attrs={"class": "usa-radio__input"}),
        error_messages={"required": "Choose a diagnostic."},
    )


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def site_inspection_context(
    server: Server, page: SitePage, plans: ServerPlans, user: User | AnonymousUser
) -> dict[str, object]:
    """What the selected site's inspection card needs."""
    identifier = page.identifier
    return {
        "server": server,
        "identifier": identifier,
        "wpix_plans": plans,
        "wpix_latest": plans.latest,
        "wpix_token": plans_token(plans),
        "wpix_form": InspectionForm(),
        "wpix_can_prepare": user.has_perms(INSPECT_AUTHORITY.prepare),
        "wpix_can_run": user.has_perms(INSPECT_AUTHORITY.apply),
        "wpix_result": (
            latest_result(server.pk, identifier) if user.has_perms(RESULT_PERMISSION) else None
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
    plans = read_site_inspection(server, page.identifier)
    context = site_inspection_context(server, page, plans, request.user)
    context.update(site=page.site, site_page=page, wpix_focus=focus, wpix_problem=problem)
    latest = plans.latest
    if problem:
        context["announcement"] = problem
    elif latest is not None and (focus or (shown is not None and shown != context["wpix_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "wordpress/_site_inspection_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *INSPECT_AUTHORITY.view),
    raise_exception=True,
)
def site_inspection_plans(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """The selected site's inspection card, polled while a remote operation is active."""
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    if not _is_fragment_request(request):
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    return _fragment(request, server, page, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *INSPECT_AUTHORITY.prepare),
    raise_exception=True,
)
def site_inspection_prepare(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    target = f"{reverse('site_wordpress', args=[pk, identifier])}#site-wordpress-inspection"
    refused = stale_refusal(
        request,
        page,
        partial=_is_fragment_request(request),
        fragment=partial(_fragment, request, server, page, focus=True),
        target=target,
    )
    if refused is not None:
        return refused
    form = InspectionForm(request.POST)
    if not form.is_valid():
        problem = "Choose one of the named diagnostics."
        if _is_fragment_request(request):
            return _fragment(request, server, page, focus=True, problem=problem, status=422)
        messages.error(request, problem)
        return redirect(target)
    try:
        queued = request_inspection_preparation(
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
            f"Barectl queued a WordPress inspection review for site {identifier}. Nothing "
            "runs on the server until you apply the reviewed plan.",
        )
    return redirect(target)
