"""The change engine's pages: prepare, review, apply, check and close
(docs/adr/0035-one-change-engine-with-effect-derived-consent.md)."""

import json
from dataclasses import replace
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
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from servers.preparation import decide_for_server, stored_server_facts
from sites.preparation import decide_for_site

from . import change_requirements, engine, preparation, services
from .consent import PREPARE_PERMISSIONS, permissions_for
from .forms import (
    AcknowledgeForm,
    ChangeApplyForm,
    ChangeConfirmationForm,
    SharedApplyForm,
)
from .models import (
    MANAGE_SECRETS,
    VIEW_CHANGES,
    ChangePreparation,
    ChangeReview,
    Consent,
)
from .presentation import (
    ChangeView,
    NextAction,
    RunView,
    blocking_operation,
    change_view,
    run_view,
)

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
    requirements = change_requirements.requirements_for(kind_slug)
    decision = decide_for_server(server_state(server), user, requirements)
    if not decision.allowed:
        messages.error(request, decision.sentence)
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
        f"Server check requested for {server.name}.",
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
    fragment = _is_fragment_request(request)
    view = change_view(row)
    context = _change_context(request, row, view, fragment=fragment)
    response = render(
        request,
        "operations/_change_status.html" if fragment else "operations/change.html",
        context,
    )
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


def _change_context(
    request: HttpRequest,
    row: services.ChangeRow,
    view: ChangeView,
    *,
    fragment: bool = False,
) -> dict[str, object]:
    preparation = row.preparation
    review = view.review
    state = server_state(preparation.server) if preparation.server is not None else None
    can_apply = _can_apply(request, view) and _apply_decision(preparation.server, state).allowed
    out_of_date = bool(
        review is not None
        and review.run_id is None
        and (review.expired or review.connection_changed)
    )
    other = blocking_operation(state.other_operation) if state is not None else None
    can_prepare_again, can_prepare_again_reason = _prepare_again_state(request, preparation, state)
    context: dict[str, object] = {
        "change": view,
        "server": preparation.server,
        "other_operation": other,
        "can_apply": can_apply and other is None,
        "out_of_date": out_of_date,
        "apply_reason": (
            "Another computer is changing this server."
            if other is not None
            else ""
            if can_apply or out_of_date
            else _apply_reason(request, view, state)
        ),
        "can_prepare_again": can_prepare_again,
        "can_prepare_again_reason": can_prepare_again_reason,
        "shared_form": SharedApplyForm(),
        "kind_form": ChangeApplyForm(),
        "confirmation_form": ChangeConfirmationForm(),
        "creation_banner": _creation_banner(request, preparation, view=None),
        "focus_heading": fragment and not view.active,
    }
    if fragment:
        if view.active and view.check is not None:
            if request.GET.get("shown") != view.check.token:
                context["announcement"] = (
                    f"{view.check.label}. {view.check.reads} server reads finished."
                )
        elif view.review is not None:
            context["announcement"] = "Barectl finished checking the server."
        else:
            context["announcement"] = "Barectl could not finish checking the server."
    return context


def _apply_reason(request: HttpRequest, view: ChangeView, state: DiscoveryState | None) -> str:
    """Why the confirm screen shows no apply control, in one plain sentence."""
    review = view.review
    if review is None:
        return ""
    if review.run_id:
        return "This change already ran."
    if not review.eligible:
        return "Barectl refused this change. Its reasons are under Show details."
    if review.no_changes:
        return "Barectl found nothing to change."
    decision = _apply_decision(
        review.review.preparation.server if review.review.preparation else None,
        state,
    )
    if not decision.allowed:
        return decision.sentence or (
            "Barectl has no current manageable observation of this server, so it will not "
            "apply changes."
        )
    if not request.user.has_perms(review.permissions):
        return "Your role may view this change but not apply it."
    return ""


def _prepare_again_decision(
    request: HttpRequest, preparation: ChangePreparation, state: DiscoveryState | None
) -> preparation.Decision | None:
    """The same card requirement set the kind's offered change used.

    A site change is decided against the site's current facts, so a partly applied,
    not-following or unreadable site withholds Try again just as it withholds the card.
    """
    kind = engine.kind_of(preparation.kind_slug)
    server = preparation.server
    user = request.user
    if kind is None or server is None or state is None or not isinstance(user, User):
        return None
    requirements = change_requirements.requirements_for(preparation.kind_slug, preparation.inputs)
    if not requirements.site:
        return decide_for_server(state, user, requirements)
    identifier = preparation.inputs.get("identifier")
    if not isinstance(identifier, str):
        return None
    return decide_for_site(state, user, identifier, requirements)


def _prepare_again_state(
    request: HttpRequest, preparation: ChangePreparation, state: DiscoveryState | None
) -> tuple[bool, str]:
    if preparation.server is None:
        return False, ""
    decision = _prepare_again_decision(request, preparation, state)
    allowed = (
        request.user.has_perm("servers.view_server") and decision is not None and decision.allowed
    )
    reason = (
        decision.sentence
        if not allowed and decision is not None and request.user.has_perm("servers.view_server")
        else ""
    )
    return allowed, reason


@require_POST
@login_required
def change_prepare_again(request: HttpRequest, operation_id: int) -> HttpResponse:
    """Prepare a fresh confirmation of the same kind and inputs (#179, Journey 7).

    A presentation convenience over the existing prepare service: the stored inputs are
    read here, never from the POST, so a forged request cannot change what is prepared.
    """
    row = services.read_change(operation_id)
    if row is None:
        raise Http404
    _may_view(request)
    preparation = row.preparation
    server = preparation.server
    if server is None:
        raise Http404
    user = _user(request)
    state = server_state(server)
    decision = _prepare_again_decision(request, preparation, state)
    if decision is None or not request.user.has_perm("servers.view_server"):
        raise PermissionDenied
    if not decision.allowed:
        messages.error(request, decision.sentence)
        return redirect("change_detail", operation_id=operation_id)
    try:
        queued = services.request_prepare(
            server, user, preparation.kind_slug, inputs=preparation.inputs
        )
    except ValueError:
        messages.error(
            request,
            "Barectl cannot prepare this change again from its stored answers. Start it "
            "again from the page that offers it.",
        )
        return redirect("change_detail", operation_id=operation_id)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.warning(
            request,
            "Barectl is running another remote operation for this server. Prepare the "
            "change again after it finishes.",
        )
        return redirect("change_detail", operation_id=operation_id)
    messages.success(request, "A fresh server check was requested.")
    return redirect("change_detail", operation_id=queued.pk)


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


def _apply_decision(server: Server | None, state: DiscoveryState | None) -> preparation.Decision:
    """The run admission rule: the host's standing, freshness and recognized contract.

    The same decision prepares and applies a change, so its sentence must be valid for
    both. The gate must not decide whether a reviewed change runs. Another active change
    is not a reason to refuse an apply; the native mutation lock decides that when the run
    starts (spec #507, US20).
    """
    if server is None or state is None:
        return preparation.Decision(False)
    return preparation.decide(stored_server_facts(state), None, preparation.EMPTY)


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
    user = _user(request)
    state = server_state(row.preparation.server) if row.preparation.server is not None else None
    decision = _apply_decision(row.preparation.server, state)
    if not decision.allowed:
        messages.error(request, decision.sentence)
        return redirect("change_detail", operation_id=operation_id)
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
    if review.acknowledgement:
        acknowledged = ChangeApplyForm(request.POST).is_valid() and acknowledged
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
        "Barectl started the change on the server. Its outcome is established from the "
        "server itself.",
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
    view = run_view(run)
    tab = "logs" if request.GET.get("tab") == "logs" else "progress"
    return render(request, "operations/run.html", _run_context(request, view, tab=tab))


def _may_take(request: HttpRequest, action: NextAction, can_prepare_again: bool) -> bool:
    if action.kind == "again":
        return can_prepare_again
    return not action.permission or request.user.has_perm(action.permission)


def _run_context(
    request: HttpRequest, view: RunView, *, tab: str = "progress"
) -> dict[str, object]:
    run = view.run
    permissions = permissions_for(view.consent, writes_secrets=run.review.writes_secrets)
    preparation = run.review.preparation
    state = (
        server_state(preparation.server)
        if preparation is not None and preparation.server is not None
        else None
    )
    can_prepare_again, prepare_again_reason = (
        _prepare_again_state(request, preparation, state)
        if preparation is not None
        else (False, "")
    )
    plain = view.plain
    next_reason = ""
    if plain.next is not None and not _may_take(request, plain.next, can_prepare_again):
        if plain.next.kind == "again":
            next_reason = prepare_again_reason
        plain = replace(plain, next=None)
    return {
        "run": view,
        "plain": plain,
        "server": run.server,
        "tab": tab,
        "can_check": view.reconciling,
        "can_acknowledge": view.reconciling and request.user.has_perms(permissions),
        "acknowledge_form": AcknowledgeForm(),
        "creation_banner": _creation_banner(request, preparation, view=view),
        "next_reason": next_reason,
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
        messages.success(request, "Barectl is checking what happened on the server.")
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
            "Barectl will close this run as outcome unknown only if it can prove the run "
            "can no longer start or still be running.",
        )
    else:
        messages.warning(
            request,
            "Only a reconciling run whose latest check found no native record can be closed "
            "as outcome unknown.",
        )
    return redirect("run_detail", operation_id=operation_id)
