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

from .forms import ChallengeForm
from .handler import AUTHORITY
from .services import read_tls_plans, request_challenge_preparation

BUSY = (
    "Barectl is running another remote operation for this server. Prepare the TLS plan after "
    "it finishes."
)
INVALID = "Correct the site identifier."


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def tls_context(
    server: Server, plans: ServerPlans, form: ChallengeForm | None = None
) -> dict[str, object]:
    """What the server page's TLS plan section needs; the server page includes it too."""
    return {
        "server": server,
        "tls_plans": plans,
        "tls_latest": plans.latest,
        "tls_form": form or ChallengeForm(),
        "tls_token": plans_token(plans),
    }


def _fragment(
    request: HttpRequest,
    server: Server,
    *,
    shown: str | None = None,
    focus: bool = False,
    problem: str = "",
    form: ChallengeForm | None = None,
    status: int = 200,
) -> HttpResponse:
    plans = read_tls_plans(server)
    context = tls_context(server, plans, form)
    context.update(tls_focus=focus, tls_problem=problem)
    latest = plans.latest
    if latest is not None and (focus or (shown is not None and shown != context["tls_token"])):
        context["announcement"] = latest.announcement
    response = render(request, "tls/_tls_update.html", context, status=status)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@never_cache
@require_GET
@login_required
@permission_required(AUTHORITY.view, raise_exception=True)
def server_tls_plans(request: HttpRequest, pk: int) -> HttpResponse:
    """The TLS plan section, polled while a remote operation is active for the server."""
    server = get_object_or_404(Server, pk=pk)
    if not _is_fragment_request(request):
        return redirect("server_detail", pk=pk)
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
        return redirect(f"{reverse('server_detail', args=[pk])}#tls-plans")
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
    return redirect(f"{reverse('server_detail', args=[pk])}#tls-plans")
