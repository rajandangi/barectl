"""docs/wordpress.md#wp-cli-setup, #php-runtime, #installation-review and
#finishing-a-partial-installation"""

from functools import partial

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
from servers.discovery_state import SitePage, server_state
from servers.models import Server
from servers.site_access import shown_site, stale_refusal

from .forms import FinishForm, InstallForm
from .handler import AUTHORITY, INSTALL_AUTHORITY
from .models import PlanRuntimeCapability, PlanWordpressRuntime, PlanWpcliTool
from .presentation import site_prerequisites
from .services import (
    read_site_finish,
    read_site_install,
    read_site_runtime,
    read_wordpress_plans,
    request_finish_preparation,
    request_install_preparation,
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


def site_install_context(
    server: Server,
    page: SitePage,
    plans: ServerPlans,
    user: User | AnonymousUser,
    *,
    form: InstallForm | None = None,
) -> dict[str, object]:
    """What the selected site's installation card needs. ``page`` has a site."""
    identifier = page.identifier
    site = page.site
    state = server_state(server)
    plans_visible = user.has_perms(AUTHORITY.view)
    runtime = None
    tool = None
    if plans_visible:
        review = (
            PlanWordpressRuntime.objects.filter(
                identifier=identifier, plan__preparation__server=server
            )
            .select_related("plan")
            .order_by("-plan__collected_at", "-pk")
            .first()
        )
        if review is not None:
            capabilities = tuple(PlanRuntimeCapability.objects.filter(plan=review.plan))
            runtime = (review, capabilities, review.plan.collected_at)
        row = (
            PlanWpcliTool.objects.filter(plan__preparation__server=server)
            .select_related("plan")
            .order_by("-plan__collected_at", "-pk")
            .first()
        )
        tool = None if row is None else (row, row.plan.collected_at)
    prerequisites = (
        []
        if site is None
        else site_prerequisites(
            site,
            observed_at=state.snapshot.collected_at if state.snapshot else None,
            runtime=runtime,
            tool=tool,
            plans_visible=plans_visible,
            urls={
                "database": reverse("site_database", args=[server.pk, identifier]),
                "https": reverse("site_https", args=[server.pk, identifier]),
                "wpcli": f"{reverse('server_advanced', args=[server.pk])}#wordpress-plans",
            },
        )
    )
    return {
        "server": server,
        "identifier": identifier,
        "state": state,
        "snapshot": state.snapshot,
        "wpin_plans": plans,
        "wpin_latest": plans.latest,
        "wpin_token": plans_token(plans),
        "wpin_form": form or InstallForm(names=site.domains if site else ()),
        "wpin_prerequisites": prerequisites,
        "wpin_can_prepare": user.has_perms(INSTALL_AUTHORITY.prepare),
    }


def _site_install_fragment(
    request: HttpRequest,
    server: Server,
    page: SitePage,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    form: InstallForm | None = None,
    status: int = 200,
) -> HttpResponse:
    plans = read_site_install(server, page.identifier)
    context = site_install_context(server, page, plans, request.user, form=form)
    context.update(site=page.site, site_page=page, wpin_focus=focus, wpin_problem=problem)
    latest = plans.latest
    if problem:
        context["announcement"] = problem
    elif form is not None and form.errors:
        context["announcement"] = "The installation review request has errors."
    elif latest is not None and (focus or (shown is not None and shown != context["wpin_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "wordpress/_site_install_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *INSTALL_AUTHORITY.view),
    raise_exception=True,
)
def site_install_plans(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """The selected site's installation card, polled while a remote operation is active."""
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    if not _is_fragment_request(request):
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    return _site_install_fragment(request, server, page, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *INSTALL_AUTHORITY.prepare),
    raise_exception=True,
)
def site_install_prepare(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    target = f"{reverse('site_wordpress', args=[pk, identifier])}#site-wordpress-install"
    refused = stale_refusal(
        request,
        page,
        partial=_is_fragment_request(request),
        fragment=partial(_site_install_fragment, request, server, page, focus=True),
        target=target,
    )
    if refused is not None:
        return refused
    form = InstallForm(request.POST, names=page.site.domains if page.site else ())
    if not form.is_valid():
        if _is_fragment_request(request):
            return _site_install_fragment(request, server, page, focus=True, form=form, status=422)
        from servers.views import site_page_response

        return site_page_response(
            request, pk, identifier, "wordpress", wordpress_form=form, status=422
        )
    try:
        queued = request_install_preparation(server, user, identifier, form.metadata())
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _site_install_fragment(
            request, server, page, focus=True, problem="" if queued else BUSY
        )
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a WordPress installation review for site {identifier}. "
            "Nothing changes.",
        )
    return redirect(target)


def site_finish_context(
    server: Server,
    page: SitePage,
    plans: ServerPlans,
    user: User | AnonymousUser,
    *,
    form: FinishForm | None = None,
) -> dict[str, object]:
    """What the selected site's Finish card needs. ``page`` has a site."""
    return {
        "server": server,
        "identifier": page.identifier,
        "wpfn_plans": plans,
        "wpfn_latest": plans.latest,
        "wpfn_token": plans_token(plans),
        "wpfn_form": form or FinishForm(),
        "wpfn_can_prepare": user.has_perms(INSTALL_AUTHORITY.prepare),
    }


def _site_finish_fragment(
    request: HttpRequest,
    server: Server,
    page: SitePage,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    form: FinishForm | None = None,
    status: int = 200,
) -> HttpResponse:
    plans = read_site_finish(server, page.identifier)
    context = site_finish_context(server, page, plans, request.user, form=form)
    context.update(site=page.site, site_page=page, wpfn_focus=focus, wpfn_problem=problem)
    latest = plans.latest
    if problem:
        context["announcement"] = problem
    elif form is not None and form.errors:
        context["announcement"] = "The Finish review request has errors."
    elif latest is not None and (focus or (shown is not None and shown != context["wpfn_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "wordpress/_site_finish_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *INSTALL_AUTHORITY.view),
    raise_exception=True,
)
def site_finish_plans(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """The selected site's Finish card, polled while a remote operation is active."""
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    if not _is_fragment_request(request):
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    return _site_finish_fragment(request, server, page, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(
    ("servers.view_server", "discovery.view_siteobservation", *INSTALL_AUTHORITY.prepare),
    raise_exception=True,
)
def site_finish_prepare(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    page = shown_site(server, identifier)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    target = f"{reverse('site_wordpress', args=[pk, identifier])}#site-wordpress-finish"
    refused = stale_refusal(
        request,
        page,
        partial=_is_fragment_request(request),
        fragment=partial(_site_finish_fragment, request, server, page, focus=True),
        target=target,
    )
    if refused is not None:
        return refused
    form = FinishForm(request.POST)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _site_finish_fragment(request, server, page, focus=True, form=form, status=422)
        from servers.views import site_page_response

        return site_page_response(
            request, pk, identifier, "wordpress", finish_form=form, status=422
        )
    try:
        queued = request_finish_preparation(server, user, identifier, form.metadata())
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _site_finish_fragment(
            request, server, page, focus=True, problem="" if queued else BUSY
        )
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a WordPress Finish review for site {identifier}. Nothing changes.",
        )
    return redirect(target)
