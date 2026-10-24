"""docs/sites.md#creating-a-site"""

from dataclasses import dataclass
from typing import Literal

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

from bootstrap.standing import Standing
from dashboard.middleware import is_htmx_request
from discovery.presentation import VIEW_SITES, present_sites
from operations import services as change_services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server

from . import continuation, prerequisites
from .forms import HttpSiteForm, LaravelSiteForm, WordPressSiteForm

BUSY = (
    "Barectl is running another remote operation for this server. Prepare the site plan after "
    "it finishes."
)


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def creation_section(user: User | AnonymousUser) -> Literal["sites", "advanced"]:
    """Creation begins from Sites; an account that may not view site observations keeps the
    Advanced copy of the form."""
    return "sites" if user.has_perm(VIEW_SITES) else "advanced"


def creation_url(user: User | AnonymousUser, pk: int) -> str:
    return f"{reverse(f'server_{creation_section(user)}', args=[pk])}#site-plans"


def _create_options(
    state: DiscoveryState, platform: str, step: continuation.CreationStep | None
) -> tuple[tuple[str, ...], tuple[tuple[str, int], ...], dict[str, object]]:
    """The PHP choices, the installable ones, and the create form's initial values."""
    choices = prerequisites.php_choices(state)
    versions = tuple(choice.entry for choice in choices if choice.installed)
    installable = prerequisites.installable(choices)
    snapshot = state.snapshot
    defaults = snapshot.collected.runtime_defaults if snapshot is not None else None
    initial: dict[str, object] = (
        {"php_version": defaults.php}
        if defaults is not None and not defaults.php_problem and defaults.php in versions
        else {}
    )
    if step is not None and step.platform == platform:
        initial = step.initial()
    return versions, installable, initial


def _can_prepare(state: DiscoveryState, *, has_choices: bool, reason: str) -> bool:
    snapshot = state.snapshot
    standing = snapshot.collected.standing if snapshot is not None else None
    return (
        standing is not None
        and standing.standing == Standing.TARGET_STACK
        and state.can_prepare_changes
        and not change_services.read_changes(state.server).polling
        and has_choices
        and not reason
    )


def http_site_context(
    server: Server,
    form: HttpSiteForm | None = None,
    step: continuation.CreationStep | None = None,
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    versions, installable, initial = _create_options(state, "http", step)
    return {
        "http_site_form": form
        if form is not None
        else HttpSiteForm(php_versions=versions, installable=installable, initial=initial),
        "http_site_has_choices": bool(versions) or bool(installable),
        "http_site_installable": bool(installable),
        "http_site_observed_at": snapshot.collected_at if snapshot is not None else None,
        "http_site_can_prepare": _can_prepare(
            state, has_choices=bool(versions) or bool(installable), reason=""
        ),
        "http_site_continuation": step if step is not None and step.platform == "http" else None,
    }


def laravel_site_context(
    server: Server,
    form: LaravelSiteForm | None = None,
    step: continuation.CreationStep | None = None,
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    versions, installable, initial = _create_options(state, "laravel", step)
    engine = prerequisites.engine_step(state, "laravel")
    return {
        "laravel_site_form": form
        if form is not None
        else LaravelSiteForm(php_versions=versions, installable=installable, initial=initial),
        "laravel_site_has_choices": bool(versions) or bool(installable),
        "laravel_site_installable": bool(installable),
        "laravel_site_observed_at": snapshot.collected_at if snapshot is not None else None,
        "laravel_site_reason": engine.reason,
        "laravel_site_step": engine if engine.needed else None,
        "laravel_site_can_prepare": _can_prepare(
            state, has_choices=bool(versions) or bool(installable), reason=engine.reason
        ),
        "laravel_site_continuation": (
            step if step is not None and step.platform == "laravel" else None
        ),
    }


def wordpress_site_context(
    server: Server,
    form: WordPressSiteForm | None = None,
    step: continuation.CreationStep | None = None,
) -> dict[str, object]:
    state = server_state(server)
    snapshot = state.snapshot
    versions, installable, initial = _create_options(state, "wordpress", step)
    engine = prerequisites.engine_step(state, "wordpress")
    return {
        "wordpress_site_form": form
        if form is not None
        else WordPressSiteForm(php_versions=versions, installable=installable, initial=initial),
        "wordpress_site_has_choices": bool(versions) or bool(installable),
        "wordpress_site_installable": bool(installable),
        "wordpress_site_observed_at": snapshot.collected_at if snapshot is not None else None,
        "wordpress_site_reason": engine.reason,
        "wordpress_site_step": engine if engine.needed else None,
        "wordpress_site_can_prepare": _can_prepare(
            state, has_choices=bool(versions) or bool(installable), reason=engine.reason
        ),
        "wordpress_site_continuation": (
            step if step is not None and step.platform == "wordpress" else None
        ),
    }


@dataclass(frozen=True)
class StepRequest:
    kind: str
    selection: str
    step_title: str
    continue_label: str


def _requested_step(
    platform: str, state: DiscoveryState, posted: str, selection: str
) -> StepRequest | None:
    """The Step 1 install this create request needs, or ``None`` to prepare the site."""
    engine = prerequisites.engine_step(state, platform)
    if engine.reason:
        return None
    if engine.needed:
        chosen = engine.engines[0][0]
        for candidate, _label in engine.engines:
            if posted == f"engine:{candidate}":
                chosen = candidate
                break
        label = next(label for candidate, label in engine.engines if candidate == chosen)
        return StepRequest(
            "install_database_engine",
            chosen,
            f"Step 1: install {label} on this server",
            f"Continue creating the {continuation.PLATFORM_LABELS[platform]}",
        )
    choices = prerequisites.php_choices(state)
    entry = posted.partition(":")[2] if posted.startswith("php:") else selection
    if any(choice.entry == entry and choice.installed for choice in choices):
        return None
    missing = next(
        (choice for choice in choices if choice.entry == entry and not choice.installed), None
    )
    if missing is None:
        return None
    return StepRequest(
        "add_runtime",
        missing.entry,
        f"Step 1: install {missing.version_label} on this server",
        f"Continue creating the {continuation.PLATFORM_LABELS[platform]}",
    )


def _create_answers(platform: str, cleaned: dict[str, object]) -> dict[str, object]:
    answers: dict[str, object] = {}
    for name in continuation.ANSWER_FIELDS[platform]:
        value = cleaned.get(name, "")
        answers[name] = " ".join(value) if name == "names" and isinstance(value, tuple) else value
    return answers


def _step_response(
    request: HttpRequest,
    server: Server,
    user: User,
    platform: str,
    state: DiscoveryState,
    cleaned: dict[str, object],
) -> HttpResponse | None:
    """Queue the missing prerequisite as Step 1 and keep the answers, or ``None``."""
    posted = request.POST.get("step", "")
    if posted.startswith("engine:"):
        chosen = posted.partition(":")[2]
        offered = {
            candidate for candidate, _label in prerequisites.engine_step(state, platform).engines
        }
        if chosen not in offered:
            messages.error(
                request,
                "That database engine is not offered for the site you are creating. "
                "Nothing was queued.",
            )
            return redirect("server_sites", pk=server.pk)
    step = _requested_step(platform, state, posted, str(cleaned["php_version"]))
    if step is None:
        return None
    try:
        preparation = change_services.request_prepare(
            server,
            user,
            step.kind,
            inputs={"version": 1, "selection": step.selection},
        )
    except OperationRefused:
        messages.error(
            request,
            "The server connection changed. Nothing was queued; reload this page and try again.",
        )
        return redirect("server_sites", pk=server.pk)
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(request, "This step is unavailable. Run discovery and prepare a new review.")
        return redirect("server_sites", pk=server.pk)
    if preparation is None:
        messages.warning(request, BUSY)
        return redirect("server_sites", pk=server.pk)
    continuation.remember(
        request,
        continuation.CreationStep(
            preparation_id=preparation.pk,
            server_id=server.pk,
            platform=platform,
            kind=step.kind,
            selection=step.selection,
            step_title=step.step_title,
            continue_label=step.continue_label,
            answers=_create_answers(platform, cleaned),
        ),
    )
    messages.success(
        request,
        f"Barectl queued {step.step_title} for {server.name}. Nothing changes until its "
        "review is applied; your answers are kept for the next step.",
    )
    destination = reverse("change_detail", args=[preparation.pk])
    if _is_fragment_request(request):
        return HttpResponse(headers={"HX-Redirect": destination})
    return redirect(destination)


def _stale_wordpress_site(request: HttpRequest, pk: int, form: WordPressSiteForm) -> HttpResponse:
    problem = (
        "The server connection changed. Reload this page and run discovery before "
        "preparing a fresh WordPress site review. Nothing was queued."
    )
    retained = WordPressSiteForm(
        {
            "identifier": form.cleaned_data["identifier"],
            "names": " ".join(form.cleaned_data["names"]),
            "title": form.cleaned_data["title"],
            "admin_username": form.cleaned_data["admin_username"],
            "admin_email": form.cleaned_data["admin_email"],
            "php_version": form.cleaned_data["php_version"],
            "http_only": form.cleaned_data["http_only"],
        },
        php_versions=(form.cleaned_data["php_version"],),
    )
    if _is_fragment_request(request):
        fresh = get_object_or_404(Server, pk=pk)
        response = render(
            request,
            "sites/_wordpress_create.html",
            {
                "server": fresh,
                **wordpress_site_context(fresh, retained),
                "wordpress_site_focus": True,
                "wordpress_site_problem": problem,
            },
            status=409,
        )
        patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
        return response
    from servers.views import server_page

    messages.error(request, problem)
    return server_page(request, pk, "sites", wordpress_site_form=retained, status=409)


def _stale_laravel_site(request: HttpRequest, pk: int, form: LaravelSiteForm) -> HttpResponse:
    problem = (
        "The server connection changed. Reload this page and run discovery before "
        "preparing a fresh Laravel site review. Nothing was queued."
    )
    retained = LaravelSiteForm(
        {
            "identifier": form.cleaned_data["identifier"],
            "names": " ".join(form.cleaned_data["names"]),
            "repository": form.cleaned_data["repository"],
            "branch": form.cleaned_data["branch"],
            "php_version": form.cleaned_data["php_version"],
            "fingerprint": form.cleaned_data["fingerprint"],
            "http_only": form.cleaned_data["http_only"],
        },
        php_versions=(form.cleaned_data["php_version"],),
    )
    if _is_fragment_request(request):
        fresh = get_object_or_404(Server, pk=pk)
        response = render(
            request,
            "sites/_laravel_create.html",
            {
                "server": fresh,
                **laravel_site_context(fresh, retained),
                "laravel_site_focus": True,
                "laravel_site_problem": problem,
            },
            status=409,
        )
        patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
        return response
    from servers.views import server_page

    messages.error(request, problem)
    return server_page(request, pk, "sites", laravel_site_form=retained, status=409)


def _stale_http_site(request: HttpRequest, pk: int, form: HttpSiteForm) -> HttpResponse:
    problem = (
        "The server connection changed. Reload this page and run discovery before "
        "preparing a fresh site review. Nothing was queued."
    )
    retained = HttpSiteForm(
        {
            "identifier": form.cleaned_data["identifier"],
            "names": " ".join(form.cleaned_data["names"]),
            "php_version": form.cleaned_data["php_version"],
            "http_only": form.cleaned_data["http_only"],
        },
        php_versions=(form.cleaned_data["php_version"],),
    )
    if _is_fragment_request(request):
        fresh = get_object_or_404(Server, pk=pk)
        response = render(
            request,
            "sites/_http_create.html",
            {
                "server": fresh,
                **http_site_context(fresh, retained),
                "http_site_focus": True,
                "http_site_problem": problem,
            },
            status=409,
        )
        patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
        return response
    from servers.views import server_page

    messages.error(request, problem)
    return server_page(request, pk, "sites", http_site_form=retained, status=409)


SiteForm = HttpSiteForm | LaravelSiteForm | WordPressSiteForm


def _stale_site(request: HttpRequest, pk: int, platform: str, form: SiteForm) -> HttpResponse:
    if platform == "http" and isinstance(form, HttpSiteForm):
        return _stale_http_site(request, pk, form)
    if platform == "laravel" and isinstance(form, LaravelSiteForm):
        return _stale_laravel_site(request, pk, form)
    if platform == "wordpress" and isinstance(form, WordPressSiteForm):
        return _stale_wordpress_site(request, pk, form)
    raise ValueError("Unknown site creation form.")


def _finish_creation(
    request: HttpRequest,
    server: Server,
    user: User,
    platform: str,
    state: DiscoveryState,
    form: SiteForm,
    *,
    kind_slug: str,
    inputs: dict[str, object],
) -> HttpResponse:
    step_response = _step_response(request, server, user, platform, state, form.cleaned_data)
    if step_response is not None:
        return step_response
    continuation.forget(request)
    try:
        preparation = change_services.request_prepare(server, user, kind_slug, inputs=inputs)
    except OperationRefused:
        return _stale_site(request, server.pk, platform, form)
    except Server.DoesNotExist:
        raise Http404 from None
    except ValueError:
        messages.error(
            request, "This site request is unavailable. Run discovery and prepare a new review."
        )
        return redirect("server_sites", pk=server.pk)
    if preparation is None:
        messages.warning(request, BUSY)
        return redirect("server_sites", pk=server.pk)
    destination = reverse("change_detail", args=[preparation.pk])
    if _is_fragment_request(request):
        return HttpResponse(headers={"HX-Redirect": destination})
    return redirect(destination)


@never_cache
@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def server_http_site_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    state = server_state(server)
    context = http_site_context(server, step=continuation.requested_step(request, pk))
    versions, installable, _initial = _create_options(state, "http", None)
    form = HttpSiteForm(request.POST, php_versions=versions, installable=installable)
    if not form.is_valid():
        from servers.views import server_page

        if _is_fragment_request(request):
            response = render(
                request,
                "sites/_http_create.html",
                {"server": server, **http_site_context(server, form), "http_site_focus": True},
                status=422,
            )
            patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
            return response
        return server_page(request, pk, "sites", http_site_form=form, status=422)
    if not context["http_site_can_prepare"]:
        messages.warning(
            request, "Run discovery and resolve the server's findings before creating a site."
        )
        return redirect("server_sites", pk=pk)
    return _finish_creation(
        request,
        server,
        user,
        "http",
        state,
        form,
        kind_slug="create_http_site",
        inputs={
            "version": 1,
            "identifier": form.cleaned_data["identifier"],
            "names": list(form.cleaned_data["names"]),
            "selection": form.cleaned_data["php_version"],
            "https": not form.cleaned_data["http_only"],
        },
    )


LARAVEL_CREATE_SLUG = "create_laravel_site"


@never_cache
@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def server_laravel_site_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    state = server_state(server)
    context = laravel_site_context(server, step=continuation.requested_step(request, pk))
    versions, installable, _initial = _create_options(state, "laravel", None)
    form = LaravelSiteForm(request.POST, php_versions=versions, installable=installable)
    if not form.is_valid():
        from servers.views import server_page

        if _is_fragment_request(request):
            response = render(
                request,
                "sites/_laravel_create.html",
                {
                    "server": server,
                    **laravel_site_context(server, form),
                    "laravel_site_focus": True,
                },
                status=422,
            )
            patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
            return response
        return server_page(request, pk, "sites", laravel_site_form=form, status=422)
    if not context["laravel_site_can_prepare"]:
        messages.warning(
            request,
            str(context["laravel_site_reason"])
            or "Run discovery and resolve the server's findings before creating a site.",
        )
        return redirect("server_sites", pk=pk)
    return _finish_creation(
        request,
        server,
        user,
        "laravel",
        state,
        form,
        kind_slug=LARAVEL_CREATE_SLUG,
        inputs={
            "version": 1,
            "identifier": form.cleaned_data["identifier"],
            "names": list(form.cleaned_data["names"]),
            "selection": form.cleaned_data["php_version"],
            "https": not form.cleaned_data["http_only"],
            "repository": form.cleaned_data["repository"],
            "branch": form.cleaned_data["branch"],
            "fingerprint": form.cleaned_data["fingerprint"],
        },
    )


WORDPRESS_CREATE_SLUG = "create_wordpress_site"


@never_cache
@require_POST
@login_required
@permission_required(
    (*PREPARE_PERMISSIONS, VIEW_SITES, "operations.manage_secrets"), raise_exception=True
)
def server_wordpress_site_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    state = server_state(server)
    context = wordpress_site_context(server, step=continuation.requested_step(request, pk))
    versions, installable, _initial = _create_options(state, "wordpress", None)
    form = WordPressSiteForm(request.POST, php_versions=versions, installable=installable)
    if not form.is_valid():
        from servers.views import server_page

        if _is_fragment_request(request):
            response = render(
                request,
                "sites/_wordpress_create.html",
                {
                    "server": server,
                    **wordpress_site_context(server, form),
                    "wordpress_site_focus": True,
                },
                status=422,
            )
            patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
            return response
        return server_page(request, pk, "sites", wordpress_site_form=form, status=422)
    if not context["wordpress_site_can_prepare"]:
        messages.warning(
            request,
            str(context["wordpress_site_reason"])
            or "Run discovery and resolve the server's findings before creating a site.",
        )
        return redirect("server_sites", pk=pk)
    return _finish_creation(
        request,
        server,
        user,
        "wordpress",
        state,
        form,
        kind_slug=WORDPRESS_CREATE_SLUG,
        inputs={
            "version": 1,
            "identifier": form.cleaned_data["identifier"],
            "names": list(form.cleaned_data["names"]),
            "selection": form.cleaned_data["php_version"],
            "https": not form.cleaned_data["http_only"],
            "title": form.cleaned_data["title"],
            "admin_username": form.cleaned_data["admin_username"],
            "admin_email": form.cleaned_data["admin_email"],
        },
    )


@never_cache
@require_GET
@login_required
@permission_required(("servers.view_server", VIEW_SITES), raise_exception=True)
def site_list(request: HttpRequest) -> HttpResponse:
    states = [server_state(server) for server in Server.objects.order_by("name", "pk")]
    return render(
        request,
        "sites/list.html",
        {
            "rows": [
                {
                    "state": state,
                    "sites": present_sites(state.snapshot.collected.sites)
                    if state.snapshot
                    else None,
                }
                for state in states
            ],
            "can_create_sites": request.user.has_perms(PREPARE_PERMISSIONS),
        },
    )
