"""docs/dashboard-workflows.md#site-pages"""

from typing import Protocol

from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect

from sites import names as site_names

from .discovery_state import SitePage, server_state, site_page
from .models import Server

STALE_SITE = "Refresh observations before changing this site. Nothing was queued."


def shown_site(server: Server, identifier: str) -> SitePage:
    """The site from the server's last complete observation; refuse one it does not show."""
    if not site_names.valid_identifier(identifier):
        raise Http404
    page = site_page(server_state(server), identifier)
    if not page.found:
        raise Http404
    return page


class Fragment(Protocol):
    """Renders a site section with a problem shown, for a partial request."""

    def __call__(self, *, problem: str, status: int) -> HttpResponse: ...


def stale_refusal(
    request: HttpRequest,
    page: SitePage,
    *,
    partial: bool,
    fragment: Fragment,
    target: str,
) -> HttpResponse | None:
    """Refuse a change to a site whose observation is stale, or ``None`` to proceed."""
    if page.current:
        return None
    if partial:
        return fragment(problem=STALE_SITE, status=409)
    messages.warning(request, STALE_SITE)
    return redirect(target)
