from collections.abc import Callable
from urllib.parse import urlsplit

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.http.response import HttpResponseRedirectBase
from django.shortcuts import resolve_url


def is_htmx_request(request: HttpRequest) -> bool:
    return request.headers.get("HX-Request") == "true"


class HtmxAuthenticationMiddleware:
    """docs/frontend-assets.md#htmx-4"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponseBase]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponseBase:
        response = self.get_response(request)
        if not is_htmx_request(request):
            return response
        if isinstance(response, HttpResponseRedirectBase) and self._is_sign_in(response.url):
            return HttpResponse(status=204, headers={"HX-Redirect": response.url})
        if response.status_code == 403:
            response.headers["HX-Refresh"] = "true"
        return response

    @staticmethod
    def _is_sign_in(url: str) -> bool:
        return urlsplit(url).path == urlsplit(resolve_url(settings.LOGIN_URL)).path
