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
from operations.presentation import blocking_operation
from runtimes.defaults import NODE_CHOICES
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from servers.page import (
    CANNOT_BE_MANAGED,
    CHECKING,
    CONNECTION_FAILED,
    NEEDS_SETUP,
    NOT_CHECKED,
    READY,
    status_line,
)

from . import continuation, prerequisites
from .forms import (
    CREATE_PLATFORMS,
    CreateSiteForm,
    HttpSiteForm,
    LaravelSiteForm,
    WordPressSiteForm,
)

BUSY = (
    "Barectl is running another remote operation for this server. Prepare the site plan after "
    "it finishes."
)
CREATE_PLATFORM_VALUES = frozenset(value for value, _label in CREATE_PLATFORMS)


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
    initial: dict[str, object] = {"php_version": prerequisites.preselected(state, choices)}
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


def create_site_context(
    server: Server,
    form: CreateSiteForm | None = None,
    step: continuation.CreationStep | None = None,
    *,
    problem: str = "",
    domain_values: list[str] | None = None,
) -> dict[str, object]:
    """The one Create site page: platform, PHP version, domains and More options."""
    state = server_state(server)
    snapshot = state.snapshot
    choices = prerequisites.php_choices(state)
    versions = tuple(choice.entry for choice in choices if choice.installed)
    installable = prerequisites.installable(choices)
    _versions, _installable, initial = _create_options(state, "http", step)
    if form is None:
        form = CreateSiteForm(php_versions=versions, installable=installable, initial=initial)
    selected = str(form["php_version"].value() or "")
    tiles = list(choices)
    if selected and selected not in {choice.entry for choice in tiles}:
        tiles.append(prerequisites.PhpChoice(selected, True, 0))
    domains = (
        list(domain_values) if domain_values is not None else str(initial.get("names", "")).split()
    )
    return {
        "create_site_form": form,
        "create_site_platforms": CREATE_PLATFORMS,
        "create_site_selected_platform": str(form["platform"].value() or "php"),
        "create_site_php_choices": tuple(
            {
                "entry": choice.entry,
                "label": choice.version_label,
                "installed": choice.installed,
                "download": (
                    "" if choice.installed else prerequisites.download_label(choice.download_size)
                ),
                "checked": choice.entry == selected,
            }
            for choice in tiles
        ),
        "create_site_has_choices": bool(tiles),
        "create_site_can_prepare": _can_prepare(state, has_choices=bool(tiles), reason=""),
        "create_site_observed_at": snapshot.collected_at if snapshot is not None else None,
        "create_site_domains": domains or [""],
        "create_site_identifier": str(form["identifier"].value() or ""),
        "create_site_continuation": (
            step if step is not None and step.platform == "http" else None
        ),
        "create_site_problem": problem,
        "create_site_node_choices": (
            tuple(
                row.entry
                for row in snapshot.collected.runtimes
                if row.entry in NODE_CHOICES and row.path and row.manageable
            )
            if snapshot is not None
            else ()
        ),
    }


_NOT_READY = {
    NEEDS_SETUP: (
        "This server is not set up yet. Set it up first, then create a site.",
        "server_setup",
    ),
    CHECKING: (
        "Barectl is checking this server. Create the site when the check finishes.",
        "server_sites",
    ),
    CONNECTION_FAILED: (
        "Barectl cannot reach this server. Check the connection first.",
        "server_settings",
    ),
    NOT_CHECKED: (
        "Barectl has not checked this server yet. Check the connection first.",
        "server_settings",
    ),
    CANNOT_BE_MANAGED: (
        "Barectl cannot manage this server, so it cannot create a site on it.",
        "server_advanced",
    ),
}


def _ready_servers() -> list[Server]:
    """The servers whose last check found a target stack and no later doubt."""
    return [
        server
        for server in Server.objects.order_by("name", "pk")
        if status_line(server_state(server)) == READY
    ]


def _create_page(
    request: HttpRequest,
    server: Server,
    form: CreateSiteForm | None = None,
    *,
    problem: str = "",
    domain_values: list[str] | None = None,
    status: int = 200,
) -> HttpResponse:
    state = server_state(server)
    step = continuation.requested_step(request, server.pk)
    context: dict[str, object] = {
        "server": server,
        "state": state,
        "create_site_retained": form is not None,
        **create_site_context(server, form, step, problem=problem, domain_values=domain_values),
    }
    line = status_line(state)
    if line != READY:
        text, route = _NOT_READY[line]
        context["create_site_not_ready"] = text
        context["create_site_not_ready_url"] = f"{reverse(route, args=[server.pk])}" + (
            "#connection" if route in {"server_settings", "server_sites"} else ""
        )
    return render(request, "sites/create.html", context, status=status)


@never_cache
@require_GET
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def site_create(request: HttpRequest, pk: int | None = None) -> HttpResponse:
    """Create site, on the global Sites page or one server (docs/dashboard-workflows.md)."""
    if pk is not None:
        return _create_page(request, get_object_or_404(Server, pk=pk))
    ready = _ready_servers()
    requested = request.GET.get("server", "")
    if requested.isdecimal():
        chosen = next((server for server in ready if server.pk == int(requested)), None)
        if chosen is not None:
            return redirect("server_site_create", pk=chosen.pk)
        messages.error(request, "Choose a server that is ready before creating a site.")
    return render(
        request,
        "sites/create.html",
        {
            "choose_server": True,
            "ready_servers": ready,
            "selected_server": (
                int(requested) if requested.isdecimal() else (ready[0].pk if ready else None)
            ),
            "create_site_has_choices": False,
        },
    )


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
        (
            f"Step 1 of 2: add {missing.version_label} to this server"
            if platform == "http"
            else f"Step 1: install {missing.version_label} on this server"
        ),
        (
            "Continue to create the site"
            if platform == "http"
            else f"Continue creating the {continuation.PLATFORM_LABELS[platform]}"
        ),
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
    messages.error(request, problem)
    return site_create_platform_form(request, pk, "wordpress", retained)


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
    messages.error(request, problem)
    return site_create_platform_form(request, pk, "laravel", retained)


def _stale_http_site(request: HttpRequest, pk: int, form: HttpSiteForm) -> HttpResponse:
    problem = (
        "The server connection changed. Reload this page and run discovery before "
        "creating the site. Nothing was queued."
    )
    fresh = get_object_or_404(Server, pk=pk)
    state = server_state(fresh)
    choices = prerequisites.php_choices(state)
    versions = tuple(choice.entry for choice in choices if choice.installed)
    installable = prerequisites.installable(choices)
    retained_version = form.cleaned_data["php_version"]
    if retained_version not in versions and retained_version not in {
        entry for entry, _size in installable
    }:
        versions = (*versions, retained_version)
    retained = CreateSiteForm(
        {
            "platform": "php",
            "identifier": form.cleaned_data["identifier"],
            "names": " ".join(form.cleaned_data["names"]),
            "php_version": retained_version,
            "http_only": form.cleaned_data["http_only"],
        },
        php_versions=versions,
        installable=installable,
    )
    messages.error(request, problem)
    return _create_page(
        request,
        fresh,
        retained,
        problem=problem,
        domain_values=list(form.cleaned_data["names"]),
        status=409,
    )


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


def site_create_platform_form(
    request: HttpRequest, pk: int, platform: str, form: WordPressSiteForm | LaravelSiteForm
) -> HttpResponse:
    """A refused platform submission, keeping the operator's answers."""
    server = get_object_or_404(Server, pk=pk)
    state = server_state(server)
    context: dict[str, object] = {
        "server": server,
        "state": state,
        "platform": platform,
        "blocking": blocking_operation(state.other_operation),
    }
    can_prepare = request.user.has_perms(PREPARE_PERMISSIONS)
    if platform == "wordpress":
        context.update(wordpress_site_context(server, form))
        context["wordpress_site_can_prepare"] = (
            can_prepare and context["wordpress_site_can_prepare"]
        )
        context["wordpress_site_focus"] = True
    else:
        context.update(laravel_site_context(server, form))
        context["laravel_site_can_prepare"] = can_prepare and context["laravel_site_can_prepare"]
        context["laravel_site_focus"] = True
    return render(request, "sites/create_platform.html", context, status=409)


@never_cache
@require_GET
@login_required
@permission_required(("servers.view_server", VIEW_SITES), raise_exception=True)
def site_create_platform(request: HttpRequest, pk: int, platform: str) -> HttpResponse:
    """The WordPress or Laravel form the Create site page leads to."""
    if platform not in ("wordpress", "laravel"):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    state = server_state(server)
    context: dict[str, object] = {
        "server": server,
        "state": state,
        "platform": platform,
        "blocking": blocking_operation(state.other_operation),
    }
    step = continuation.requested_step(request, server.pk)
    can_prepare = request.user.has_perms(PREPARE_PERMISSIONS)
    if platform == "wordpress":
        context.update(wordpress_site_context(server, step=step))
        context["wordpress_site_can_prepare"] = (
            can_prepare and context["wordpress_site_can_prepare"]
        )
    else:
        context.update(laravel_site_context(server, step=step))
        context["laravel_site_can_prepare"] = can_prepare and context["laravel_site_can_prepare"]
    return render(request, "sites/create_platform.html", context)


@never_cache
@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def server_http_site_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    """The Create site page's POST target; WordPress and Laravel lead to their own forms."""
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    platform = request.POST.get("platform", "php")
    if platform not in CREATE_PLATFORM_VALUES:
        return _create_page(
            request,
            server,
            problem="Choose PHP, WordPress or Laravel. Nothing was queued.",
            status=422,
        )
    if platform == "wordpress":
        return redirect("site_create_platform", pk=server.pk, platform="wordpress")
    if platform == "laravel":
        return redirect("site_create_platform", pk=server.pk, platform="laravel")
    state = server_state(server)
    choices = prerequisites.php_choices(state)
    versions = tuple(choice.entry for choice in choices if choice.installed)
    installable = prerequisites.installable(choices)
    domains = request.POST.getlist("names")
    form = CreateSiteForm(request.POST, php_versions=versions, installable=installable)
    if not form.is_valid():
        return _create_page(request, server, form, domain_values=domains, status=422)
    if not _can_prepare(state, has_choices=bool(choices), reason=""):
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
    rows = [
        {
            "state": state,
            "sites": present_sites(state.snapshot.collected.sites) if state.snapshot else None,
            "ready": status_line(state) == READY,
        }
        for state in states
    ]
    return render(
        request,
        "sites/list.html",
        {
            "rows": rows,
            "can_create_sites": request.user.has_perms(PREPARE_PERMISSIONS),
            "has_ready_server": any(row["ready"] for row in rows),
        },
    )
