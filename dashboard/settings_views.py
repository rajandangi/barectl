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
    """Every offered runtime of this release, worded for installation Settings."""
    catalog = load()
    labels = {Kind.PHP: "PHP", Kind.NODE: "Node.js", Kind.TOOL: "Tool"}
    return tuple(
        {
            "language": labels[build.kind],
            "version": build.version,
            "architecture": "x86_64" if build.architecture == Architecture.X86_64 else "arm64",
        }
        for architecture in (Architecture.X86_64, Architecture.AARCH64)
        for build in catalog.offered(architecture)
        # A PHP extension the object cache loads is supply, not a runtime an operator adds.
        if build.kind in labels
    )


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
