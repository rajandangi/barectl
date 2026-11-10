"""Installation-wide Settings: the signed-in account, controller keys and this release."""

import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from runtimes.catalog import Architecture, Kind, load
from servers.credentials import approved_keys


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
@require_GET
@login_required
def settings_page(request: HttpRequest) -> HttpResponse:
    """Nothing on this page changes a server, and it makes no SSH connection."""
    return render(
        request,
        "dashboard/settings.html",
        {
            "keys": approved_keys(),
            "barectl_version": barectl_version(),
            "catalog": catalog_rows(),
        },
    )
