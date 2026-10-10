"""Encrypted browser first access.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from . import first_access


@login_required
@require_POST
@never_cache
def reveal(request: HttpRequest, run_id: int) -> HttpResponse:
    if not request.user.is_authenticated:
        raise Http404
    encrypted = first_access.reveal(request.user, run_id)
    if encrypted is None:
        raise Http404
    return JsonResponse(encrypted)
