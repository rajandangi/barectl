"""The Logs section's explicit read and rotation requests (Phase C #389)."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.cache import patch_vary_headers
from django.views.decorators.http import require_GET, require_POST

from dashboard.middleware import is_htmx_request
from discovery.presentation import VIEW_SITES
from operations import services as change_services
from operations.consent import PREPARE_PERMISSIONS
from operations.lifecycle import OperationRefused
from servers.models import Server
from sites.names import valid_identifier

from . import services
from .forms import LogFilterForm
from .sources import source


def _is_fragment_request(request: HttpRequest) -> bool:
    return is_htmx_request(request) and request.headers.get("HX-Request-Type") == "partial"


def _logs_url(pk: int, identifier: str, slug: str = "") -> str:
    url = reverse("site_logs", args=[pk, identifier])
    return f"{url}?log={slug}" if slug else url


@require_POST
@login_required
@permission_required(services.READ_PERMISSIONS, raise_exception=True)
def read_log(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """Queue one explicit read of one log; the page itself never connects."""
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    slug = request.POST.get("source", "")
    if source(slug) is None:
        raise Http404
    form = LogFilterForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Choose a valid search term and time range.")
        return redirect(_logs_url(pk, identifier, slug))
    server = get_object_or_404(Server, pk=pk)
    queued = services.request_read(
        server,
        request.user,
        identifier,
        slug,
        cursor=request.POST.get("cursor", "")[:200],
        **form.document(),
    )
    if queued is None:
        messages.error(request, "Wait for the current operation before reading this log.")
    return redirect(_logs_url(pk, identifier, slug))


@require_GET
@login_required
@permission_required(services.READ_PERMISSIONS, raise_exception=True)
def log_page(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """The stored page fragment the Logs section polls; it never issues a remote command."""
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    slug = request.GET.get("log", "")
    if source(slug) is None or not _is_fragment_request(request):
        return redirect(_logs_url(pk, identifier, slug))
    server = get_object_or_404(Server, pk=pk)
    context = services.context_for_site(server, identifier, request.user, selected=slug)
    response = render(request, "logs/_viewer.html", context)
    patch_vary_headers(response, ("HX-Request", "HX-Request-Type"))
    return response


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_rotation(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    """The reviewed repair for a site whose rotation file is missing or outside the shape."""
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    try:
        queued = change_services.request_prepare(
            server,
            request.user,
            "set_up_log_rotation",
            inputs={"version": 1, "identifier": identifier},
        )
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare again.")
        return redirect(_logs_url(pk, identifier))
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect(_logs_url(pk, identifier))
    return redirect("change_detail", operation_id=queued.pk)
