"""Simple server defaults and per-site runtime overrides."""

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from bootstrap.actions import BOOTSTRAP, authority
from bootstrap.models import Action, PhpRuntimeSnapshot
from discovery.presentation import VIEW_SITES
from node_runtimes.catalog import VERSIONS, executable
from node_runtimes.models import NodeRuntimeSnapshot
from servers.discovery_state import Status, server_state, site_page
from servers.models import Server

from .choices import is_wordpress, php_branches, set_php_choices
from .presentation import Step, stage_label, status_label


def runtime_progress_context(server: Server, identifier: str = "") -> dict[str, object]:
    from bootstrap.runtime_models import RuntimeChange as PhpChange
    from node_runtimes.models import RuntimeChange as NodeChange

    progress = []
    active = False
    for model, label, field in ((PhpChange, "PHP", "branch"), (NodeChange, "Node", "version")):
        change = model.objects.filter(server=server, identifier=identifier).order_by("-pk").first()
        if change is None:
            continue
        steps = []
        for step in change.steps.select_related("preparation", "run").order_by("position"):
            operation = step.run or step.preparation
            if operation is not None:
                steps.append(
                    Step(
                        stage_label(operation.action),
                        status_label(operation.status),
                        operation.failure,
                    )
                )
        active = active or change.status == "active"
        progress.append(
            {
                "runtime": label,
                "version": getattr(change, field),
                "status": status_label(change.status),
                "failure": change.failure,
                "steps": steps,
            }
        )
    if progress and not active:
        active = server_state(server).status in {Status.QUEUED, Status.RUNNING}
    return {
        "runtime_progress": progress,
        "runtime_changing": active,
        "runtime_identifier": identifier,
    }


@never_cache
@require_GET
@login_required
@permission_required("servers.view_server", raise_exception=True)
def runtime_progress(request: HttpRequest, pk: int, identifier: str = "") -> HttpResponse:
    if identifier and not request.user.has_perm(VIEW_SITES):
        raise PermissionDenied
    server = get_object_or_404(Server, pk=pk)
    context = runtime_progress_context(server, identifier)
    response = render(
        request,
        "hosting/_runtime_progress.html",
        {"server": server, **context},
    )
    if context["runtime_progress"] and not context["runtime_changing"]:
        response.headers["HX-Refresh"] = "true"
    return response


class PhpVersionForm(forms.Form):
    version = forms.ChoiceField(
        label="Default PHP version",
        choices=(
            ("", "Choose a PHP version"),
            *((branch, f"PHP {branch}") for branch in ("8.3", "8.4", "8.5")),
        ),
        widget=forms.Select(attrs={"class": "usa-select"}),
    )


class NodeVersionForm(forms.Form):
    version = forms.ChoiceField(
        label="Default Node version",
        choices=(
            ("", "Choose a Node version"),
            *((version, f"Node {version}") for version in VERSIONS),
        ),
        widget=forms.Select(attrs={"class": "usa-select"}),
    )


def runtime_permissions(runtime: str, identifier: str) -> tuple[str, ...]:
    if runtime == "node":
        from node_runtimes.changes import permissions

        return permissions(identifier)
    action = Action.SITE_PHP_SWITCH if identifier else Action.PHP_DEFAULT
    selected = authority(action)
    return tuple(
        dict.fromkeys((*BOOTSTRAP.prepare, *BOOTSTRAP.apply, *selected.prepare, *selected.apply))
    )


def runtime_context(
    server: Server, user: User | AnonymousUser, identifier: str = ""
) -> dict[str, object]:
    state = server_state(server)
    observed = (
        PhpRuntimeSnapshot.objects.filter(snapshot_id=state.snapshot.revision).first()
        if state.snapshot is not None
        else None
    )
    branch = observed.default_branch if observed is not None and not observed.failure else ""
    if identifier:
        page = site_page(state, identifier)
        branch = page.site.php_version if page.site is not None else ""
    node = (
        NodeRuntimeSnapshot.objects.filter(snapshot_id=state.snapshot.revision).first()
        if state.snapshot is not None
        else None
    )
    node_version = node.default if node is not None and not node.failure else ""
    if identifier and node is not None and not node.failure:
        node_version = dict(row.split() for row in node.site_pins.splitlines()).get(identifier, "")
    php_form = PhpVersionForm(initial={"version": branch})
    set_php_choices(
        php_form,
        "version",
        php_branches(state, observed, wordpress=is_wordpress(state, identifier)),
    )
    return {
        "runtime_node": node,
        "runtime_node_version": node_version,
        "runtime_node_executable": executable(node_version) if node_version in VERSIONS else "",
        "runtime_php": observed,
        "runtime_stale": state.snapshot_notice,
        "runtime_php_form": php_form,
        "runtime_node_form": NodeVersionForm(
            initial={"version": node_version}, auto_id="id_node_%s"
        ),
        "runtime_identifier": identifier,
        "runtime_can_php": user.has_perms(runtime_permissions("php", identifier)),
        "runtime_can_node": user.has_perms(runtime_permissions("node", identifier)),
        **runtime_progress_context(server, identifier),
    }


@require_POST
@login_required
@permission_required("servers.view_server", raise_exception=True)
def change_runtime(
    request: HttpRequest, pk: int, runtime: str, identifier: str = ""
) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    if identifier and not user.has_perm(VIEW_SITES):
        raise PermissionDenied
    if runtime in {"php", "node"} and not user.has_perms(runtime_permissions(runtime, identifier)):
        raise PermissionDenied
    form: PhpVersionForm | NodeVersionForm
    if runtime == "php":
        form = PhpVersionForm(request.POST)
        state = server_state(server)
        observed = (
            PhpRuntimeSnapshot.objects.filter(snapshot_id=state.snapshot.revision).first()
            if state.snapshot
            else None
        )
        set_php_choices(
            form,
            "version",
            php_branches(state, observed, wordpress=is_wordpress(state, identifier)),
        )
    elif runtime == "node":
        form = NodeVersionForm(request.POST)
    else:
        raise Http404
    queued: object | None = None
    if form.is_valid():
        version: str = form.cleaned_data["version"]
        if runtime == "php":
            from bootstrap.runtime_changes import request_php_default, request_site_php_switch

            queued = (
                request_site_php_switch(server, user, identifier, version)
                if identifier
                else request_php_default(server, user, version)
            )
        else:
            from node_runtimes.changes import request_runtime_change

            queued = request_runtime_change(server, user.pk, version, identifier=identifier)
    if queued is None:
        messages.error(
            request,
            "The runtime change could not start. Check your permissions, "
            "refresh the server, or wait for its current operation.",
        )
    else:
        messages.success(
            request,
            "Runtime change started. Other sites keep their selected versions."
            if identifier
            else "Runtime change started. Existing sites keep their selected versions.",
        )
    return (
        redirect("site_detail", pk=pk, identifier=identifier)
        if identifier
        else redirect("server_setup", pk=pk)
    )
