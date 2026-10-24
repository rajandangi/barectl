"""Server Settings: the optional certificate contact email (Phase B #444)."""

from dataclasses import dataclass
from typing import cast

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server

from .certificate_email import ABSENT, OUTSIDE, SET, SLUG, UNREADABLE, valid_email

FILTERED_STATES = (ABSENT, SET)
READ_STATES = (ABSENT, SET, OUTSIDE, UNREADABLE)


class CertificateEmailForm(forms.Form):
    email = forms.CharField(
        required=False,
        max_length=254,
        label="Certificate contact email",
        widget=forms.EmailInput(
            attrs={
                "class": "usa-input",
                "autocomplete": "email",
                "spellcheck": "false",
                "aria-describedby": "id_email-hint",
            }
        ),
        help_text=(
            "Optional. Leave it empty to remove Caddy's email line. Caddy sends certificate "
            "authority notices here."
        ),
    )

    def clean_email(self) -> str:
        value = str(self.cleaned_data.get("email", "")).strip()
        if not valid_email(value):
            raise forms.ValidationError(
                "Enter one email address, such as ops@example.com, or leave it empty."
            )
        return value


@dataclass(frozen=True)
class CertificateEmailPanel:
    observed: bool
    state: str
    email: str
    saved: str
    can_prepare: bool


def context_for_server(
    server: Server,
    user: User | AnonymousUser,
    state: DiscoveryState | None = None,
) -> dict[str, object]:
    state = state or server_state(server)
    snapshot = state.snapshot
    setting = snapshot.collected.certificate_email_state if snapshot else ""
    observed = setting in READ_STATES
    email = snapshot.collected.certificate_email if snapshot else ""
    saved = server.certificate_email
    initial = saved if not observed else email if setting == SET else ""
    can_prepare = (
        observed
        and setting in FILTERED_STATES
        and state.can_prepare_changes
        and user.has_perms(PREPARE_PERMISSIONS)
        and not state.polling
    )
    panel = CertificateEmailPanel(
        observed=observed,
        state=setting,
        email=email if setting == SET else "",
        saved=saved,
        can_prepare=can_prepare,
    )
    return {
        "certificate_email_panel": panel,
        "certificate_email_form": CertificateEmailForm(initial={"email": initial}),
        "certificate_email_problem": (
            "The main Caddy configuration is outside supported settings for the certificate "
            "contact email. Resolve its global options through ordinary administration."
            if setting == OUTSIDE
            else "The certificate contact email could not be read from the main Caddy "
            "configuration."
            if setting == UNREADABLE
            else ""
        ),
    }


@require_POST
@login_required
@permission_required(PREPARE_PERMISSIONS, raise_exception=True)
def prepare_certificate_email(request: HttpRequest, pk: int) -> HttpResponse:
    if not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    context = context_for_server(server, request.user)
    panel = cast(CertificateEmailPanel, context["certificate_email_panel"])
    form = CertificateEmailForm(request.POST)
    if not form.is_valid():
        errors = form.errors.get("email")
        messages.error(request, str(errors[0]) if errors else "Enter one email address.")
        return redirect("server_settings", pk=pk)
    if not panel.observed:
        messages.error(
            request,
            "Choose the certificate contact email from a current, complete server "
            "observation. Run discovery and resolve the server's findings first.",
        )
        return redirect("server_settings", pk=pk)
    if not panel.can_prepare:
        messages.error(
            request,
            "The certificate contact email cannot change while another operation runs or "
            "the server's setting is outside supported settings.",
        )
        return redirect("server_settings", pk=pk)
    email = str(form.cleaned_data["email"])
    try:
        queued = services.request_prepare(
            server,
            request.user,
            SLUG,
            inputs={"version": 1, "email": email},
        )
    except OperationRefused:
        messages.error(request, "The saved connection changed. Refresh and prepare a new review.")
        return redirect("server_settings", pk=pk)
    except ValueError:
        messages.error(request, "Enter one email address, or leave it empty to remove it.")
        return redirect("server_settings", pk=pk)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("server_settings", pk=pk)
    server.certificate_email = email
    server.save(update_fields=["certificate_email"])
    messages.success(
        request,
        "Barectl queued a review of Caddy's certificate contact email. Nothing changes until "
        "its review is applied.",
    )
    return redirect("change_detail", operation_id=queued.pk)
