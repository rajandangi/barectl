"""Explicit WordPress password recovery in the normal dashboard."""

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import AnonymousUser, User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from servers.models import Server
from sites.names import valid_identifier
from wordpress import first_access, inputs
from wordpress.access_reset_models import AccessResetIntent
from wordpress.access_reset_services import PERMISSIONS, request_access_reset

from .models import HostingCreation, HostingCreationStep
from .presentation import status_label


class AccessForm(forms.Form):
    admin_login = forms.CharField(
        label="Administrator username",
        max_length=60,
        widget=forms.TextInput(attrs={"class": "usa-input", "autocomplete": "username"}),
    )
    first_access_spki = forms.CharField(max_length=1024, widget=forms.HiddenInput)

    def clean_admin_login(self) -> str:
        login: str = self.cleaned_data["admin_login"]
        problem = inputs.login_problem(login)
        if problem:
            raise forms.ValidationError(problem)
        return login

    def clean_first_access_spki(self) -> str:
        key: str = self.cleaned_data["first_access_spki"]
        try:
            first_access.validate_key(key)
        except ValueError as invalid:
            raise forms.ValidationError(str(invalid)) from invalid
        return key


def access_context(
    server: Server, user: User | AnonymousUser, identifier: str, *, form: AccessForm | None = None
) -> dict[str, object]:
    if not user.has_perms(PERMISSIONS):
        return {}
    latest = (
        AccessResetIntent.objects.filter(
            preparation__server=server, preparation__access_request__identifier=identifier
        )
        .select_related("preparation", "run")
        .order_by("-pk")
        .first()
    )
    creation = HostingCreation.objects.filter(
        server=server, identifier=identifier, application="wordpress"
    ).first()
    run_id = (
        latest.run_id
        if latest is not None
        else HostingCreationStep.objects.filter(creation=creation, stage="wordpress_install")
        .values_list("run_id", flat=True)
        .first()
        if creation is not None
        else None
    )
    delivery = (
        first_access.read_delivery(user, run_id)
        if isinstance(user, User) and run_id is not None
        else None
    )
    return {
        "access_shown": True,
        "access_form": form
        or AccessForm(initial={"admin_login": creation.admin_login if creation else ""}),
        "access_intent": latest,
        "access_status": status_label(latest.status) if latest else "",
        "access_delivery": delivery,
    }


@never_cache
@require_POST
@login_required
@permission_required(PERMISSIONS, raise_exception=True)
def reset_access(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    form = AccessForm(request.POST)
    if form.is_valid():
        prepared = request_access_reset(
            server,
            user.pk,
            identifier,
            form.cleaned_data["admin_login"],
            form.cleaned_data["first_access_spki"],
        )
        if prepared is not None:
            messages.success(request, "Administrator password reset started. Follow its progress.")
            return redirect("site_wordpress", pk=pk, identifier=identifier)
        messages.error(
            request,
            "The reset could not start. Wait for the current operation and refresh the site.",
        )
    return render(
        request,
        "hosting/access.html",
        {
            "server": server,
            "identifier": identifier,
            **access_context(server, user, identifier, form=form),
        },
        status=422,
    )


@never_cache
@require_GET
@login_required
@permission_required(PERMISSIONS, raise_exception=True)
def access_progress(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    return render(
        request,
        "hosting/_wordpress_access.html",
        {
            "server": server,
            "identifier": identifier,
            **access_context(server, request.user, identifier),
        },
    )
