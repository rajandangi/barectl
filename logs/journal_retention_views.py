"""Server Settings: the observed journal retention policy and its reviewed change (#549, #551).

docs/adr/0044-own-journald-log-retention-in-a-separate-drop-in.md. The card reads the latest
stored observation only; opening Settings issues no SSH. Only Not configured and Managed
states offer the two-choice form; Outside keeps its plain reason and refuses a direct POST.
"""

from dataclasses import dataclass
from typing import cast

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from operations import change_requirements, preparation, services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from servers.preparation import decide_for_server

from .journal_retention import (
    DISK_CAP_CHOICES,
    DISK_CAP_LABELS,
    MANAGED,
    MAX_AGE_CHOICES,
    MAX_AGE_LABELS,
    NOT_CHECKED,
    NOT_CONFIGURED,
    OUTSIDE,
)
from .journal_retention_change import SLUG

FORM_STATES = (MANAGED, NOT_CONFIGURED)
DEFAULT_DISK_CAP = "1G"
DEFAULT_MAX_AGE = "3months"


class JournalRetentionForm(forms.Form):
    """The two fixed choices, always written together (ADR 0044)."""

    disk_cap = forms.ChoiceField(
        choices=[(choice, DISK_CAP_LABELS[choice]) for choice in DISK_CAP_CHOICES],
        label="Disk cap",
        widget=forms.Select(attrs={"class": "usa-select"}),
    )
    max_age = forms.ChoiceField(
        choices=[(choice, MAX_AGE_LABELS[choice]) for choice in MAX_AGE_CHOICES],
        label="Maximum age",
        widget=forms.Select(attrs={"class": "usa-select"}),
    )


@dataclass(frozen=True)
class JournalRetentionPanel:
    """One card state: what was observed, or that no current observation exists."""

    checked: bool
    state: str
    reason: str = ""
    disk_cap: str = ""
    max_age: str = ""
    disk_cap_label: str = ""
    max_age_label: str = ""
    gate_reason: str = ""
    can_prepare: bool = False
    initial_disk_cap: str = ""
    initial_max_age: str = ""

    @property
    def managed(self) -> bool:
        return self.checked and self.state == MANAGED

    @property
    def outside(self) -> bool:
        return self.checked and self.state == OUTSIDE

    @property
    def not_configured(self) -> bool:
        return self.checked and self.state == NOT_CONFIGURED


def context_for_server(
    state: DiscoveryState,
    user: User | AnonymousUser,
) -> dict[str, object]:
    snapshot = state.snapshot
    retention = snapshot.collected.journal_retention if snapshot is not None else None
    checked = snapshot is not None and state.snapshot_notice is None and retention is not None
    decision = (
        decide_for_server(state, user, change_requirements.JOURNAL_RETENTION)
        if isinstance(user, User)
        else preparation.Decision(False)
    )
    current = retention if checked and retention is not None else None
    initial_disk_cap = (
        current.disk_cap
        if current is not None and current.state == MANAGED
        else DEFAULT_DISK_CAP
        if current is not None and current.state == NOT_CONFIGURED
        else ""
    )
    initial_max_age = (
        current.max_age
        if current is not None and current.state == MANAGED
        else DEFAULT_MAX_AGE
        if current is not None and current.state == NOT_CONFIGURED
        else ""
    )
    panel = JournalRetentionPanel(
        checked=checked,
        state=current.state if current is not None else NOT_CHECKED,
        reason=current.reason if current is not None else "",
        disk_cap=current.disk_cap if current is not None else "",
        max_age=current.max_age if current is not None else "",
        disk_cap_label=(
            DISK_CAP_LABELS.get(current.disk_cap, current.disk_cap) if current is not None else ""
        ),
        max_age_label=(
            MAX_AGE_LABELS.get(current.max_age, current.max_age) if current is not None else ""
        ),
        gate_reason=decision.sentence,
        can_prepare=(current is not None and current.state in FORM_STATES and decision.allowed),
        initial_disk_cap=initial_disk_cap,
        initial_max_age=initial_max_age,
    )
    return {
        "journal_retention_panel": panel,
        "journal_retention_form": JournalRetentionForm(
            initial={"disk_cap": initial_disk_cap, "max_age": initial_max_age}
        ),
    }


@require_POST
@login_required
@permission_required(PREPARE_PERMISSIONS, raise_exception=True)
def prepare_journal_retention(request: HttpRequest, pk: int) -> HttpResponse:
    if not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    state = server_state(server)
    context = context_for_server(state, request.user)
    panel = cast(JournalRetentionPanel, context["journal_retention_panel"])
    form = JournalRetentionForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Choose one disk cap and one maximum age from the list.")
        return redirect("server_settings", pk=pk)
    if not panel.checked:
        messages.error(
            request,
            "Choose the server's log retention policy from a current, complete server "
            "observation. Run discovery and resolve the server's findings first.",
        )
        return redirect("server_settings", pk=pk)
    decision = decide_for_server(state, request.user, change_requirements.JOURNAL_RETENTION)
    if not decision.allowed:
        messages.error(request, decision.sentence)
        return redirect("server_settings", pk=pk)
    if panel.state not in FORM_STATES:
        messages.error(
            request,
            "Log retention cannot change while the server's setting is outside supported settings.",
        )
        return redirect("server_settings", pk=pk)
    try:
        queued = services.request_prepare(
            server,
            request.user,
            SLUG,
            inputs={
                "version": 1,
                "disk_cap": str(form.cleaned_data["disk_cap"]),
                "max_age": str(form.cleaned_data["max_age"]),
            },
        )
    except OperationRefused:
        messages.error(request, "The saved connection changed. Refresh and prepare a new review.")
        return redirect("server_settings", pk=pk)
    except ValueError:
        messages.error(request, "Choose one disk cap and one maximum age from the list.")
        return redirect("server_settings", pk=pk)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("server_settings", pk=pk)
    messages.success(
        request,
        "Barectl queued a review of the server's log retention. Nothing changes until its "
        "review is applied.",
    )
    return redirect("change_detail", operation_id=queued.pk)
