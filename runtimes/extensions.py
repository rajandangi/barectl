"""The PHP object-cache client Barectl supplies, and the catalog build that provides it.

The decision (Phase C #390) is phpredis, the Hydra-built ``redis`` extension package for
each PHP runtime, loaded from its locked store path. It is a catalog build, not a runtime:
a site enables it for its own master and CLI wrappers (docs/runtimes.md#php-extensions).
Predis is not needed, so :data:`CLIENT` names phpredis and :data:`PHPHREDIS_AVAILABLE`
is true. Phase C's object-cache changes (#392, #393) read both instead of re-deciding.

The package's internal layout is proven natively, not assumed: the shared object is
``<build>/lib/php/extensions/redis.so`` inside the build the catalog lock names
(``disposable/test_php_client.py``).
"""

from .catalog import Architecture, Build, Kind, load

# The client Phase C's WordPress plugin and Laravel application use for a site cache.
CLIENT = "phpredis"
PHPHREDIS_AVAILABLE = True
# Every PHP runtime the catalog offers, to its extension entry.
ENTRIES = {"php84": "php84_redis", "php85": "php85_redis"}
_SHARED_OBJECT = "/lib/php/extensions/redis.so"


def entry_for(runtime: str) -> str:
    """The catalog entry that supplies ``runtime``'s redis extension."""
    try:
        return ENTRIES[runtime]
    except KeyError:
        raise ValueError("This catalog entry is not a PHP runtime.") from None


def build(architecture: Architecture, runtime: str) -> Build | None:
    """The locked redis extension build for ``runtime``, or ``None`` when it is unavailable."""
    try:
        entry = entry_for(runtime)
    except ValueError:
        return None
    return next(
        (
            item
            for item in load().offered(architecture)
            if item.entry == entry and item.kind is Kind.EXTENSION
        ),
        None,
    )


def shared_object(item: Build) -> str:
    """The extension's shared object inside its locked build."""
    return item.path + _SHARED_OBJECT


def path(architecture: Architecture, runtime: str) -> str:
    """The shared object's exact store path, or ``""`` when the catalog does not supply it."""
    item = build(architecture, runtime)
    return "" if item is None else shared_object(item)


def available(architecture: Architecture, runtime: str) -> bool:
    """Whether this release supplies the client for ``runtime`` on ``architecture``."""
    return build(architecture, runtime) is not None
