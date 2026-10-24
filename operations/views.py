"""The change engine's pages: prepare, review, apply, check and close
(docs/adr/0035-one-change-engine-with-effect-derived-consent.md)."""

import json
from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from dashboard.middleware import is_htmx_request
from servers.discovery_state import server_state
from servers.models import Server

from . import engine, services
from .consent import PREPARE_PERMISSIONS, permissions_for
from .forms import (
    AcknowledgeForm,
    ChangeApplyForm,
    ChangeConfirmationForm,
    SharedApplyForm,
)
from .inputs import InputShape
from .models import MANAGE_SECRETS, VIEW_CHANGES, ChangePreparation, ChangeReview, Consent
from .presentation import ChangeView, RunView, change_view, run_view

if TYPE_CHECKING:
    from sites.continuation import StepBanner


def _is_fragment_request(request: HttpRequest) -> bool:
    # History restores and body-targeted requests need the complete page.
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def _may_view(request: HttpRequest) -> None:
    if not request.user.has_perm(VIEW_CHANGES):
        raise PermissionDenied


def _user(request: HttpRequest) -> User:
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    return user


@never_cache
@require_GET
@login_required
def server_changes(request: HttpRequest, pk: int) -> HttpResponse:
    """The server's changes page: what the one change engine prepares, reviews and runs."""
    _may_view(request)
    if not request.user.has_perm("servers.view_server"):
        raise PermissionDenied
    server = get_object_or_404(Server, pk=pk)
    changes = services.read_changes(server)
    discovery_state = server_state(server)
    can_prepare = request.user.has_perms(PREPARE_PERMISSIONS) and (
        discovery_state.can_prepare_changes
    )
    context = {
        "server": server,
        "rows": [change_view(row) for row in changes.rows],
        "kinds": [
            kind
            for kind in engine.registered_kinds()
            if can_prepare and kind.input_shape == InputShape.SELECTION and not kind.input_choices
        ],
        "can_prepare": can_prepare,
        "standing_refusal": not discovery_state.can_prepare_changes,
        "busy": changes.polling,
    }
    return render(request, "operations/changes.html", context)


@require_POST
@login_required
def server_change_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = _user(request)
    kind_slug = request.POST.get("kind", "")
    kind = engine.kind_of(kind_slug)
    permissions = (
        (*PREPARE_PERMISSIONS, MANAGE_SECRETS)
        if kind is not None and kind.writes_secrets
        else PREPARE_PERMISSIONS
    )
    if not user.has_perm("servers.view_server") or not user.has_perms(permissions):
        raise PermissionDenied
    if not server_state(server).can_prepare_changes:
        messages.error(
            request,
            "This server has no current manageable host-standing observation. Run discovery "
            "and resolve any Not manageable findings before preparing changes.",
        )
        return redirect("server_changes", pk=pk)
    if kind is None:
        messages.error(request, "Choose one of the supported kinds of change.")
        return redirect("server_changes", pk=pk)
    try:
        inputs = (
            {"version": 1, "selection": request.POST.get("selection", "")}
            if kind.input_choices
            else None
        )
        queued = services.request_prepare(server, user, kind_slug, inputs=inputs)
    except ValueError:
        messages.error(request, "Choose an offered runtime before preparing its review.")
        return redirect("server_stack", pk=pk)
    except Server.DoesNotExist:
        # Removed by another request after this one loaded it.
        raise Http404 from None
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another remote operation for this server. Prepare the "
            "change after it finishes.",
        )
        return redirect("server_changes", pk=pk)
    messages.success(
        request,
        f"Barectl queued a review of {kind.label} for {server.name}. Nothing changes "
        "until its review is applied.",
    )
    return redirect("change_detail", operation_id=queued.pk)


@never_cache
@require_GET
@login_required
def change_detail(request: HttpRequest, operation_id: int) -> HttpResponse:
    row = services.read_change(operation_id)
    if row is None:
        raise Http404
    _may_view(request)
    view = change_view(row)
    context: dict[str, object] = {
        "change": view,
        "server": row.preparation.server,
        "can_apply": _can_apply(request, view) and _server_can_prepare(row.preparation.server),
        "shared_form": SharedApplyForm(),
        "kind_form": ChangeApplyForm(),
        "confirmation_form": ChangeConfirmationForm(),
        "creation_banner": _creation_banner(request, row.preparation, view=None),
    }
    return render(request, "operations/change.html", context)


def _creation_banner(
    request: HttpRequest, preparation: ChangePreparation | None, *, view: RunView | None
) -> StepBanner | None:
    """docs/sites.md#step-1-a-missing-runtime-or-database-engine"""
    from sites import continuation

    if preparation is None or preparation.server_id is None:
        return None
    step = continuation.for_preparation(request, preparation.pk, preparation.server_id)
    if step is None:
        return None
    if view is None:
        return continuation.change_banner(step)
    return continuation.run_banner(step, succeeded=view.succeeded, finished=not view.active)


def _can_apply(request: HttpRequest, view: ChangeView) -> bool:
    review = view.review
    return (
        review is not None
        and review.eligible
        and not review.no_changes
        and not review.expired
        and not review.connection_changed
        and review.run_id is None
        and request.user.has_perms(review.permissions)
    )


def _server_can_prepare(server: Server | None) -> bool:
    return server is not None and server_state(server).can_prepare_changes


def _submitted_confirmation(request: HttpRequest, review: ChangeReview) -> str | None:
    """The typed value a destructive review requires, or ``None`` when it is missing."""
    if not review.confirmation:
        return ""
    form = ChangeConfirmationForm(request.POST)
    if not form.is_valid() or form.cleaned_data["confirmation"] != review.confirmation:
        return None
    return str(form.cleaned_data["confirmation"])


def _submitted_secret(request: HttpRequest, review: ChangeReview) -> bytes:
    """The confidential value a settings review asks for, gathered only from its own fields.

    A single-value kind keeps the one ``secret`` field of ADR 0032. A settings review names
    one input per changed key, and only the review's own key list is read, so a forged POST
    cannot add a value to the confidential payload (Phase B #383).
    """
    document = getattr(review, "document", {})
    fields = document.get("secret_fields") if isinstance(document, dict) else None
    if not isinstance(fields, list) or not fields:
        return request.POST.get("secret", "").encode()
    values = {
        str(field["key"]): request.POST.get(f"value_{field['key']}", "")
        for field in fields
        if isinstance(field, dict) and isinstance(field.get("key"), str)
    }
    return json.dumps({"values": values}, ensure_ascii=False).encode()


@require_POST
@login_required
def change_apply(request: HttpRequest, operation_id: int) -> HttpResponse:  # noqa: C901 - guarded applies
    """Queue the run of one reviewed change; a repeated request shows the same run."""
    row = services.read_change(operation_id)
    if row is None:
        raise Http404
    _may_view(request)
    review = row.review
    if review is None:
        raise Http404
    if not _server_can_prepare(row.preparation.server):
        messages.error(
            request,
            "This server has no current manageable host-standing observation. Run discovery "
            "and resolve any Not manageable findings before applying changes.",
        )
        return redirect("change_detail", operation_id=operation_id)
    user = _user(request)
    if not user.has_perms(
        permissions_for(Consent(review.consent), writes_secrets=review.writes_secrets)
    ):
        raise PermissionDenied
    acknowledged = True
    if review.consent == Consent.SHARED:
        acknowledged = SharedApplyForm(request.POST).is_valid()
        if not acknowledged:
            messages.error(request, services.SHARED_ACKNOWLEDGEMENT)
            return redirect("change_detail", operation_id=operation_id)
    elif review.acknowledgement:
        acknowledged = ChangeApplyForm(request.POST).is_valid()
        if not acknowledged:
            messages.error(request, services.ACKNOWLEDGEMENT_REQUIRED)
            return redirect("change_detail", operation_id=operation_id)
    confirmation = _submitted_confirmation(request, review)
    if confirmation is None:
        messages.error(request, services.CONFIRMATION_REQUIRED)
        return redirect("change_detail", operation_id=operation_id)
    secret = _submitted_secret(request, review) if review.writes_secrets else None
    requested = services.request_apply(
        review,
        user,
        acknowledged=acknowledged,
        confirmation=confirmation,
        secret=secret,
    )
    if requested.run is None:
        messages.error(request, requested.problem)
        return redirect("change_detail", operation_id=operation_id)
    messages.success(
        request,
        "Barectl queued the change for applying. Its outcome is established from the "
        "server's native evidence.",
    )
    return redirect("run_detail", operation_id=requested.run.pk)


@never_cache
@require_GET
@login_required
def run_detail(request: HttpRequest, operation_id: int) -> HttpResponse:
    run = services.read_run(operation_id)
    if run is None:
        raise Http404
    _may_view(request)
    return render(request, "operations/run.html", _run_context(request, run_view(run)))


def _run_context(request: HttpRequest, view: RunView) -> dict[str, object]:
    run = view.run
    permissions = permissions_for(view.consent, writes_secrets=run.review.writes_secrets)
    return {
        "run": view,
        "server": run.server,
        "can_check": view.reconciling,
        "can_acknowledge": view.reconciling and request.user.has_perms(permissions),
        "acknowledge_form": AcknowledgeForm(),
        "creation_banner": _creation_banner(request, run.review.preparation, view=view),
    }


@never_cache
@require_GET
@login_required
def run_status(request: HttpRequest, operation_id: int) -> HttpResponse:
    """The run's status section, polled while the worker is on it or a check is pending."""
    run = services.read_run(operation_id)
    if run is None:
        raise Http404
    _may_view(request)
    if not _is_fragment_request(request):
        return redirect("run_detail", operation_id=operation_id)
    view = run_view(run)
    context = _run_context(request, view)
    if request.GET.get("shown") != view.token:
        context["announcement"] = "The run's state changed." if view.active else "The run finished."
    response = render(request, "operations/_run_status.html", context)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@require_POST
@login_required
def run_check(request: HttpRequest, operation_id: int) -> HttpResponse:
    run = services.read_run(operation_id)
    if run is None:
        raise Http404
    _may_view(request)
    if services.request_check(operation_id):
        messages.success(request, "Barectl queued a check of this run's native outcome.")
    else:
        messages.warning(request, "Only a run whose outcome is being reconciled can be checked.")
    return redirect("run_detail", operation_id=operation_id)


@require_POST
@login_required
def run_acknowledge(request: HttpRequest, operation_id: int) -> HttpResponse:
    """docs/adr/0006-use-native-bootstrap-execution.md#unknown-outcomes"""
    run = services.read_run(operation_id)
    if run is None:
        raise Http404
    _may_view(request)
    user = _user(request)
    if not user.has_perms(
        permissions_for(Consent(run.review.consent), writes_secrets=run.review.writes_secrets)
    ):
        raise PermissionDenied
    form = AcknowledgeForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Confirm that you understand the outcome is unknown.")
    elif services.request_closure(operation_id, user):
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
    return redirect("run_detail", operation_id=operation_id)
