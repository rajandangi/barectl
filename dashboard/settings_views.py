"""Installation-wide Settings: the signed-in account, controller keys and this release."""

import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import cast

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods

from runtimes.catalog import Architecture, Kind, load
from servers.credentials import approved_keys

from .forms import AccountPasswordForm


def barectl_version() -> str:
    try:
        return version("barectl")
    except PackageNotFoundError:
        pass
    try:
        with (Path(settings.BASE_DIR) / "pyproject.toml").open("rb") as source:
            project = tomllib.load(source).get("project", {})
    except OSError, tomllib.TOMLDecodeError:
        return "unknown"
    declared = project.get("version") if isinstance(project, dict) else None
    return declared if isinstance(declared, str) else "unknown"


def catalog_rows() -> tuple[dict[str, str], ...]:
    """Offered software grouped by entry and version across server architectures."""
    catalog = load()
    labels = {Kind.PHP: "PHP", Kind.NODE: "Node.js"}
    tool_labels = {
        "caddy": "Caddy",
        "composer": "Composer",
        "fcgi": "FastCGI client",
        "haproxy": "HAProxy",
        "wp-cli": "WP-CLI",
    }
    rows: dict[tuple[str, str], dict[str, str]] = {}
    for architecture in (Architecture.X86_64, Architecture.AARCH64):
        for build in catalog.offered(architecture):
            if build.kind not in (*labels, Kind.TOOL):
                continue
            key = (build.entry, build.version)
            processor = "x86_64" if architecture == Architecture.X86_64 else "arm64"
            if key in rows:
                rows[key]["architecture"] += f", {processor}"
            else:
                rows[key] = {
                    "name": labels.get(build.kind, tool_labels.get(build.entry, build.entry)),
                    "version": build.version,
                    "architecture": processor,
                }
    return tuple(rows.values())


@never_cache
@require_http_methods(["GET", "POST"])
@login_required
@sensitive_post_parameters()
def settings_page(request: HttpRequest) -> HttpResponse:
    user = cast(User, request.user)
    form = AccountPasswordForm(user, data=request.POST if request.method == "POST" else None)
    if form.is_valid():
        form.save()
        update_session_auth_hash(request, user)
        messages.success(request, "Password changed.")
        return redirect("settings")

    return render(
        request,
        "dashboard/settings.html",
        {
            "form": form,
            "keys": approved_keys(),
            "barectl_version": barectl_version(),
            "catalog": catalog_rows(),
        },
    )
