"""Laravel's own cache wiring on the shared per-site instance (#393).

The site's `.env` names the same private Unix socket the per-site instance exposes. These
helpers are pure: the controller, the native body and discovery all compare against one
definition, so the store, host and port cannot drift.
"""

import hashlib
from typing import Final

from .convention import instance_paths

LARAVEL_KEYS: Final = ("CACHE_STORE", "REDIS_HOST", "REDIS_PORT")


def laravel_values(identifier: str) -> dict[str, str]:
    """The reviewed Laravel `.env` values for one site's own cache."""
    return {
        "CACHE_STORE": "redis",
        "REDIS_HOST": instance_paths(identifier).socket,
        "REDIS_PORT": "0",
    }


def laravel_wiring(identifier: str, entries: dict[str, str]) -> str:
    """``complete``, ``partial`` or absent for one site's Laravel cache wiring."""
    expected = laravel_values(identifier)
    if not any(key in entries for key in LARAVEL_KEYS):
        return ""
    return (
        "complete"
        if all(entries.get(key) == value for key, value in expected.items())
        else "partial"
    )


def laravel_wiring_digests(identifier: str, digests: dict[str, str]) -> str:
    """The same verdict from server-computed digests, never from the values."""
    expected = laravel_values(identifier)
    if not any(key in digests for key in LARAVEL_KEYS):
        return ""
    return (
        "complete"
        if all(
            digests.get(key) == hashlib.sha256(value.encode("utf-8")).hexdigest()
            for key, value in expected.items()
        )
        else "partial"
    )


def laravel_managed(identifier: str, entries: dict[str, str]) -> frozenset[str]:
    """The `.env` keys Barectl owns, from the native values."""
    expected = laravel_values(identifier)
    managed: set[str] = set()
    if all(entries.get(key) == expected[key] for key in ("REDIS_HOST", "REDIS_PORT")):
        managed.update(("REDIS_HOST", "REDIS_PORT"))
        if entries.get("CACHE_STORE") == expected["CACHE_STORE"]:
            managed.add("CACHE_STORE")
    return frozenset(managed)


def laravel_managed_digests(identifier: str, digests: dict[str, str]) -> frozenset[str]:
    """The same managed set from server-computed digests, never from the values."""
    expected = laravel_values(identifier)
    hashed = {
        key: hashlib.sha256(value.encode("utf-8")).hexdigest() for key, value in expected.items()
    }
    managed: set[str] = set()
    if all(digests.get(key) == hashed[key] for key in ("REDIS_HOST", "REDIS_PORT")):
        managed.update(("REDIS_HOST", "REDIS_PORT"))
        if digests.get("CACHE_STORE") == hashed["CACHE_STORE"]:
            managed.add("CACHE_STORE")
    return frozenset(managed)
