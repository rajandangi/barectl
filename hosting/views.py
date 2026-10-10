"""Explicit site creation with one authorization and retained progress."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods

from bootstrap.models import Action, PhpRuntimeSnapshot
from discovery.presentation import VIEW_SITES
from servers.discovery_state import server_state
from servers.models import Server
from tls.readiness import production_authority
from wordpress.first_access import read_delivery

from .choices import default_php_branch, php_branches, set_php_choices
from .creation import permissions, read_creation, request_creation
from .forms import CreationForm
from .models import HostingCreationStep
from .presentation import creation_progress as progress_context


def creation_context(server: Server, user: User | None = None) -> dict[str, object]:
    creation = read_creation(server)
    return {
        "hosting_creation": creation,
        **progress_context(creation),
        **first_access_context(user, creation.id if creation else None),
    }


def first_access_context(user: User | None, creation_id: int | None) -> dict[str, object]:
    run_id = (
        HostingCreationStep.objects.filter(creation_id=creation_id, stage=Action.WORDPRESS_INSTALL)
        .values_list("run_id", flat=True)
        .first()
        if creation_id
        else None
    )
    return {
        "first_access": read_delivery(user, run_id)
        if user is not None and run_id is not None
        else None
    }


@never_cache
@require_http_methods(["GET", "POST"])
@login_required
@permission_required(("servers.view_server", VIEW_SITES), raise_exception=True)
def create_site(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    state = server_state(server)
    application = request.POST.get("application", request.GET.get("application", "php"))
    if application not in {"php", "wordpress"}:
        raise Http404
    initial = {
        "application": application,
        "discovery_revision": state.snapshot.revision if state.snapshot else 0,
    }
    form = CreationForm(request.POST if request.method == "POST" else None, initial=initial)
    observed = (
        PhpRuntimeSnapshot.objects.filter(snapshot_id=state.snapshot.revision).first()
        if state.snapshot
        else None
    )
    branches = php_branches(state, observed, wordpress=application == "wordpress")
    set_php_choices(
        form,
        "php_version",
        branches,
        default_allowed=application != "wordpress"
        or default_php_branch(state, observed) in branches,
    )
    can_create = (
        state.snapshot is not None
        and state.snapshot_notice is None
        and (application != "wordpress" or bool(branches))
    )
    unavailable = (
        "WordPress is not yet qualified for this server's PHP installation. "
        "Check the server's PHP details before creating it."
        if application == "wordpress" and not branches
        else "Check the server connection before creating a site."
    )
    problem = unavailable if request.method == "POST" and not can_create else ""
    if request.method == "POST" and form.is_valid():
        wanted = form.intent()
        if not request.user.has_perms(permissions(wanted)):
            from django.core.exceptions import PermissionDenied

            raise PermissionDenied
        user = request.user
        if not isinstance(user, User):
            raise Http404
        creation = request_creation(server, user.pk, wanted) if can_create else None
        if creation is not None:
            messages.success(request, "Site creation started. Follow its progress below.")
            return redirect("hosting_creation", pk=server.pk, creation_id=creation.pk)
        problem = (
            unavailable
            if not can_create
            else (
                "Refresh the server connection or wait for its current operation "
                "to finish, then try again."
            )
        )
    return render(
        request,
        "hosting/create.html",
        {
            "server": server,
            "state": state,
            "form": form,
            "application": application,
            "problem": problem,
            "can_create": can_create,
            "unavailable": unavailable,
            "certificate_authority": production_authority(),
            "source_setup_authorization": observed is not None and observed.fresh,
        },
        status=409 if problem else 200,
    )


@never_cache
@require_GET
@login_required
@permission_required(("servers.view_server", VIEW_SITES), raise_exception=True)
def creation_progress(request: HttpRequest, pk: int, creation_id: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    creation = read_creation(server, creation_id)
    if creation is None:
        raise Http404
    template = (
        "hosting/_progress.html"
        if request.headers.get("HX-Request") == "true"
        else "hosting/progress.html"
    )
    user = request.user
    return render(
        request,
        template,
        {
            "server": server,
            "hosting_creation": creation,
            **progress_context(creation),
            **first_access_context(user if isinstance(user, User) else None, creation.id),
        },
    )
