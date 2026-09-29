"""docs/frontend-assets.md#django-integration"""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.templatetags.static import static
from django.utils.html import format_html, format_html_join
from django.utils.safestring import SafeString

STATIC_PREFIX = "dist/"


@dataclass(frozen=True, slots=True)
class ManifestChunk:
    file: str
    css: tuple[str, ...]
    imports: tuple[str, ...]
    is_entry: bool


type Manifest = dict[str, ManifestChunk]


class ManifestError(ImproperlyConfigured):
    pass


def _string_list(value: object, name: str, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ManifestError(f"Vite manifest entry {name!r} has an invalid {key!r} list.")
    return tuple(item for item in value if isinstance(item, str))


def _asset_path(value: str, name: str) -> str:
    # Hashed output paths are relative to the Vite output directory.
    if not value or value.startswith(("/", "\\")) or ".." in value.split("/"):
        raise ManifestError(f"Vite manifest entry {name!r} has an unsafe file path.")
    return value


def parse_manifest(text: str) -> Manifest:
    try:
        data: object = json.loads(text)
    except json.JSONDecodeError as error:
        raise ManifestError("The Vite manifest is not valid JSON.") from error
    if not isinstance(data, dict):
        raise ManifestError("The Vite manifest must be a JSON object.")
    manifest: Manifest = {}
    for name, chunk in data.items():
        if not isinstance(name, str) or not isinstance(chunk, dict):
            raise ManifestError("Each Vite manifest entry must be an object.")
        file = chunk.get("file")
        is_entry = chunk.get("isEntry", False)
        if not isinstance(file, str) or not isinstance(is_entry, bool):
            raise ManifestError(f"Vite manifest entry {name!r} is missing its output file.")
        manifest[name] = ManifestChunk(
            file=_asset_path(file, name),
            css=tuple(
                _asset_path(css, name) for css in _string_list(chunk.get("css"), name, "css")
            ),
            imports=_string_list(chunk.get("imports"), name, "imports"),
            is_entry=is_entry,
        )
    return manifest


# The modification time is part of the key, so a rebuild is read without a restart.
@lru_cache(maxsize=4)
def _read_manifest(path: Path, modified: int) -> Manifest:
    return parse_manifest(path.read_text(encoding="utf-8"))


def load_manifest(path: Path) -> Manifest:
    try:
        modified = path.stat().st_mtime_ns
    except FileNotFoundError as error:
        raise ManifestError(
            f"Vite manifest not found at {path}. Run `npm run build` before serving or "
            "collecting static files, or set BARECTL_VITE_DEV_SERVER_URL in development."
        ) from error
    return _read_manifest(path, modified)


def _imported_chunks(manifest: Manifest, chunk: ManifestChunk) -> list[ManifestChunk]:
    seen: set[str] = set()
    ordered: list[ManifestChunk] = []

    def visit(current: ManifestChunk) -> None:
        for key in current.imports:
            if key in seen:
                continue
            seen.add(key)
            try:
                imported = manifest[key]
            except KeyError as error:
                raise ManifestError(f"Vite manifest import {key!r} is missing.") from error
            visit(imported)
            ordered.append(imported)

    visit(chunk)
    return ordered


def production_tags(manifest: Manifest, entry: str, *, classic: bool = False) -> SafeString:
    try:
        chunk = manifest[entry]
    except KeyError as error:
        raise ManifestError(f"Vite entry {entry!r} is not in the manifest.") from error
    if not chunk.is_entry:
        raise ManifestError(f"Vite manifest item {entry!r} is not an entry point.")
    if classic and chunk.imports:
        raise ManifestError(f"Classic Vite entry {entry!r} cannot import other chunks.")
    imported = _imported_chunks(manifest, chunk)
    stylesheets = list(dict.fromkeys([*chunk.css, *(css for item in imported for css in item.css)]))

    def url(file: str) -> str:
        return static(STATIC_PREFIX + file)

    return format_html(
        "{}{}{}",
        format_html_join(
            "", '<link rel="stylesheet" href="{}">', ((url(css),) for css in stylesheets)
        ),
        format_html(
            '<script src="{}"></script>' if classic else '<script type="module" src="{}"></script>',
            url(chunk.file),
        ),
        format_html_join(
            "", '<link rel="modulepreload" href="{}">', ((url(item.file),) for item in imported)
        ),
    )


def development_tags(server_url: str, entry: str) -> SafeString:
    return format_html(
        '<script type="module" src="{}/@vite/client"></script>'
        '<script type="module" src="{}/{}"></script>',
        server_url,
        server_url,
        entry,
    )


def entry_tags(entry: str, *, classic: bool = False) -> SafeString:
    if settings.VITE_DEV_SERVER_URL:
        return development_tags(settings.VITE_DEV_SERVER_URL, entry)
    return production_tags(load_manifest(settings.VITE_MANIFEST_PATH), entry, classic=classic)
