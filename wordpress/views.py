"""A WordPress site's settings section and its action preparations (Phase B #381).

Opening the section makes no SSH connection: it reads the latest observation. Preparing an
action queues a review in the worker, which reads the site's native evidence once.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from bootstrap.standing import Standing
from discovery.models import SiteState
from discovery.presentation import VIEW_SITES
from discovery.snapshot import ObservedSite
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from operations.models import MANAGE_SECRETS
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from sites.names import valid_identifier

from .actions import CORE_SLUG, PASSWORD_SLUG
from .forms import WordPressPasswordForm

CHANGED = "The saved connection changed. Refresh and prepare a new review."
BUSY = "Wait for the current operation before preparing this review."


def _site(state: DiscoveryState, identifier: str) -> ObservedSite | None:
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier),
        None,
    )


def context_for_site(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    state = server_state(server)
    site = _site(state, identifier)
    standing = state.snapshot.collected.standing if state.snapshot is not None else None
    complete = (
        site is not None
        and site.application == "wordpress"
        and not site.application_problem
        and site.state == SiteState.MANAGED
        and site.file.startswith("/etc/caddy/sites/")
        and standing is not None
        and standing.standing == Standing.TARGET_STACK
    )
    allowed = complete and state.can_prepare_changes and not services.read_changes(server).polling
    problem = ""
    if site is not None and site.application == "wordpress_partial":
        problem = site.application_problem or "The WordPress installation is incomplete."
    elif site is not None and site.application != "wordpress":
        problem = "This site is not a WordPress application."
    return {
        "wordpress_version": site.application_version if site is not None else "",
        "wordpress_problem": problem,
        "wordpress_password_form": WordPressPasswordForm(),
        "wordpress_password_can_prepare": allowed
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES, MANAGE_SECRETS)),
        "wordpress_core_can_prepare": allowed
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES)),
    }


def _prepare(
    request: HttpRequest,
    pk: int,
    identifier: str,
    *,
    slug: str,
    inputs: dict[str, object],
    problem: str,
) -> HttpResponse:
    if not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_site(server, identifier, request.user)
    allowed = (
        context["wordpress_password_can_prepare"]
        if slug == PASSWORD_SLUG
        else context["wordpress_core_can_prepare"]
    )
    if not allowed:
        messages.error(request, problem)
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    try:
        queued = services.request_prepare(server, request.user, slug, inputs=inputs)
    except OperationRefused, ValueError:
        messages.error(request, CHANGED)
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, BUSY)
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES, MANAGE_SECRETS), raise_exception=True)
def prepare_password(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    form = WordPressPasswordForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Enter a supported administrator username.")
        return redirect("site_wordpress", pk=pk, identifier=identifier)
    return _prepare(
        request,
        pk,
        identifier,
        slug=PASSWORD_SLUG,
        inputs={
            "version": 1,
            "identifier": identifier,
            "admin_username": form.cleaned_data["admin_username"],
        },
        problem="Reset a password only on a current, complete WordPress site.",
    )


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_core(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    return _prepare(
        request,
        pk,
        identifier,
        slug=CORE_SLUG,
        inputs={"version": 1, "identifier": identifier},
        problem="Verify core files only on a current, complete WordPress site.",
    )
