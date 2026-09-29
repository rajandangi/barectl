from django.conf import settings
from django.core.checks import CheckMessage, Error, register

from .vite import ManifestError, load_manifest

TEMPLATE_ENTRIES = ("uswds-init.ts", "main.ts")


@register(deploy=True)
def check_built_assets(**kwargs: object) -> list[CheckMessage]:
    if settings.VITE_DEV_SERVER_URL:
        return [
            Error(
                "BARECTL_VITE_DEV_SERVER_URL is for development only.",
                hint="Unset it and deploy the production build from `npm run build`.",
                id="dashboard.E001",
            )
        ]
    try:
        manifest = load_manifest(settings.VITE_MANIFEST_PATH)
    except ManifestError as error:
        return [Error(str(error), id="dashboard.E002")]
    return [
        Error(f"The Vite manifest has no {entry!r} entry.", id="dashboard.E003")
        for entry in TEMPLATE_ENTRIES
        if entry not in manifest
    ]
