"""docs/tls.md#preparing-a-challenge-route"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.cache import patch_vary_headers
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from bootstrap.services import ServerPlans
from bootstrap.views import plans_token
from dashboard.middleware import is_htmx_request
from servers.models import Server

from .forms import (
    ActivationForm,
    ChallengeForm,
    InstallationForm,
    IssuanceForm,
    ReadinessForm,
    StagingForm,
)
from .handler import AUTHORITY
from .installation import PERMISSIONS, request_installation
from .models import CertificateInstallation
from .services import (
    read_tls_plans,
    request_activation_preparation,
    request_challenge_preparation,
    request_issuance_preparation,
    request_readiness_preparation,
    request_setup_preparation,
    request_staging_preparation,
)

BUSY = (
    "Barectl is running another remote operation for this server. Prepare the TLS plan after "
    "it finishes."
)
INVALID = "Correct the site identifier."


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def tls_context(
    server: Server,
    plans: ServerPlans,
    *,
    form: ChallengeForm | None = None,
    readiness_form: ReadinessForm | None = None,
    staging_form: StagingForm | None = None,
    issuance_form: IssuanceForm | None = None,
    activation_form: ActivationForm | None = None,
    installation_form: InstallationForm | None = None,
) -> dict[str, object]:
    """What the server page's TLS plan section needs; the server page includes it too."""
    installation = CertificateInstallation.objects.filter(server=server).first()
    return {
        "server": server,
        "tls_plans": plans,
        "tls_latest": plans.latest,
        "tls_form": form or ChallengeForm(),
        "tls_readiness_form": readiness_form or ReadinessForm(prefix=ReadinessForm.prefix),
        "tls_staging_form": staging_form or StagingForm(prefix=StagingForm.prefix),
        "tls_issuance_form": issuance_form or IssuanceForm(prefix=IssuanceForm.prefix),
        "tls_activation_form": activation_form or ActivationForm(prefix=ActivationForm.prefix),
        "tls_token": plans_token(plans),
        "tls_installation_form": installation_form or InstallationForm(server),
        "tls_installation": installation,
        "tls_installation_active": installation is not None
        and installation.status == CertificateInstallation.Status.ACTIVE,
        "tls_installation_step": None
        if installation is None
        else installation.steps.select_related("run", "preparation").last(),
    }


def _fragment(
    request: HttpRequest,
    server: Server,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    form: ChallengeForm | None = None,
    readiness_form: ReadinessForm | None = None,
    staging_form: StagingForm | None = None,
    issuance_form: IssuanceForm | None = None,
    activation_form: ActivationForm | None = None,
    installation_form: InstallationForm | None = None,
    status: int = 200,
) -> HttpResponse:
    plans = read_tls_plans(server)
    context = tls_context(
        server,
        plans,
        form=form,
        readiness_form=readiness_form,
        staging_form=staging_form,
        issuance_form=issuance_form,
        activation_form=activation_form,
        installation_form=installation_form,
    )
    context["tls_can_install"] = request.user.has_perms(PERMISSIONS)
    context.update(
        tls_focus=focus,
        tls_problem=problem,
        tls_advanced=request.POST.get("advanced") == "1" or request.GET.get("advanced") == "1",
    )
    latest = plans.latest
    if latest is not None and (focus or (shown is not None and shown != context["tls_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "tls/_tls_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@require_POST
@login_required
@permission_required(PERMISSIONS, raise_exception=True)
def server_certificate_install(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    form = InstallationForm(server, request.POST)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, installation_form=form, status=422)
        messages.error(request, "Choose a discovered site and enter a valid contact email.")
        return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")
    if not isinstance(request.user, User):
        raise PermissionDenied
    try:
        installed = request_installation(
            server,
            request.user.pk,
            form.cleaned_data["identifier"],
            form.cleaned_data["email"],
            form.cleaned_data["snapshot"],
        )
    except Server.DoesNotExist:
        raise Http404 from None
    problem = (
        ""
        if installed is not None
        else "Installation cannot start. Another operation is active, "
        "or the site or authority is unavailable."
    )
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem=problem)
    if problem:
        messages.warning(request, problem)
    else:
        messages.success(request, "Certificate installation queued.")
    return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")


@never_cache
@require_GET
@login_required
@permission_required(AUTHORITY.view, raise_exception=True)
def server_tls_plans(request: HttpRequest, pk: int) -> HttpResponse:
    """The TLS plan section, polled while a remote operation is active for the server."""
    server = get_object_or_404(Server, pk=pk)
    if not _is_fragment_request(request):
        return redirect("server_advanced", pk=pk)
    return _fragment(request, server, shown=request.GET.get("shown"))


@require_POST
@login_required
@permission_required(AUTHORITY.prepare, raise_exception=True)
def server_challenge_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    form = ChallengeForm(request.POST)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, form=form, status=422)
        messages.error(request, INVALID)
        return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")
    try:
        queued = request_challenge_preparation(server, user, form.cleaned_data["identifier"])
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a challenge route plan preparation for {server.name}. Nothing "
            "changes.",
        )
    return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")


@require_POST
@login_required
@permission_required(AUTHORITY.prepare, raise_exception=True)
def server_setup_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    try:
        queued = request_setup_preparation(server, user)
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a renewal setup plan preparation for {server.name}. Nothing changes.",
        )
    return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")


@require_POST
@login_required
@permission_required(AUTHORITY.prepare, raise_exception=True)
def server_readiness_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    form = ReadinessForm(request.POST, prefix=ReadinessForm.prefix)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, readiness_form=form, status=422)
        messages.error(request, INVALID)
        return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")
    try:
        queued = request_readiness_preparation(server, user, form.cleaned_data["identifier"])
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a TLS readiness review for {server.name}. Nothing changes.",
        )
    return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")


@require_POST
@login_required
@permission_required(AUTHORITY.prepare, raise_exception=True)
def server_staging_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    form = StagingForm(request.POST, prefix=StagingForm.prefix)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, staging_form=form, status=422)
        messages.error(request, INVALID)
        return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")
    try:
        queued = request_staging_preparation(
            server,
            user,
            form.cleaned_data["identifier"],
            form.cleaned_data["email"],
            form.cleaned_data["authority"],
        )
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a staging order preparation for {server.name}. The review "
            "changes nothing; applying it talks to the authority.",
        )
    return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")


@require_POST
@login_required
@permission_required(AUTHORITY.prepare, raise_exception=True)
def server_issuance_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    form = IssuanceForm(request.POST, prefix=IssuanceForm.prefix)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, issuance_form=form, status=422)
        messages.error(request, INVALID)
        return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")
    try:
        queued = request_issuance_preparation(
            server,
            user,
            form.cleaned_data["identifier"],
            form.cleaned_data["email"],
        )
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued a production order preparation for {server.name}. The review "
            "changes nothing; applying it orders a real certificate.",
        )
    return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")


@require_POST
@login_required
@permission_required(AUTHORITY.prepare, raise_exception=True)
def server_activation_prepare(request: HttpRequest, pk: int) -> HttpResponse:
    server = get_object_or_404(Server, pk=pk)
    user = request.user
    if not isinstance(user, User):
        raise PermissionDenied
    form = ActivationForm(request.POST, prefix=ActivationForm.prefix)
    if not form.is_valid():
        if _is_fragment_request(request):
            return _fragment(request, server, focus=True, activation_form=form, status=422)
        messages.error(request, INVALID)
        return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")
    try:
        queued = request_activation_preparation(server, user, form.cleaned_data["identifier"])
    except Server.DoesNotExist:
        raise Http404 from None
    if _is_fragment_request(request):
        return _fragment(request, server, focus=True, problem="" if queued else BUSY)
    if queued is None:
        messages.warning(request, BUSY)
    else:
        messages.success(
            request,
            f"Barectl queued an HTTPS activation preparation for {server.name}. The review "
            "changes nothing; applying it reloads Nginx.",
        )
    return redirect(f"{reverse('server_advanced', args=[pk])}#tls-plans")
