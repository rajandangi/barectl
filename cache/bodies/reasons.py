"""The result reasons the Valkey and object-cache bodies can print (#495, #501).

The install body names the package transaction, the distribution mask and the shared
restart. The site body names the instance, wiring, plugin, verification and Laravel
environment steps it reached before it stopped.
"""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason

VALKEY_REASONS: Final = (
    ResultReason(
        "valkey_server",
        {
            Result.REFUSED: (
                "The server's resolved package set differs from the reviewed one, so Barectl "
                "stopped before changing packages. Prepare a new review."
            ),
            Result.PARTIAL: (
                "The Valkey server step stopped after the package transaction began, so "
                "valkey-server may be partly installed. Read the run's journal on the server, "
                "then prepare a new review of what remains."
            ),
        },
    ),
    ResultReason(
        "valkey_mask",
        {
            Result.PARTIAL: (
                "Valkey was installed, but Barectl could not stop and mask the distribution's "
                "shared service, so it may still run. Read the run's journal on the server, "
                "stop and mask valkey-server.service through ordinary administration, then "
                "prepare a new review."
            ),
        },
    ),
    ResultReason(
        "valkey_reload",
        {
            Result.PARTIAL: (
                "Valkey was installed and masked, but Barectl could not restart every running "
                "PHP master and site proxy, so discovery may report them outside supported "
                "settings until the server is restarted. Read the run's journal on the server, "
                "then prepare a new review."
            ),
        },
    ),
)

OBJECT_CACHE_REASONS: Final = (
    ResultReason(
        "object_cache",
        {
            Result.REFUSED: (
                "The object cache change stopped before it began, so no cache instance, "
                "connection or plugin changed. Read the run's journal, then prepare a new "
                "review."
            ),
            Result.PARTIAL: (
                "The object cache change stopped after it began. Nothing on the server was "
                "rolled back; read the run's journal, then prepare a new review that proposes "
                "only what remains."
            ),
        },
    ),
    ResultReason(
        "object_cache_instance",
        {
            Result.PARTIAL: (
                "The site's own cache instance did not start or is not the reviewed shape. "
                "Read the run's journal on the server, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "object_cache_wiring",
        {
            Result.PARTIAL: (
                "The cache instance is running, but Barectl could not finish the site's cache "
                "wiring: the WordPress connection did not complete. Read the run's journal, then "
                "prepare a new review."
            ),
        },
    ),
    ResultReason(
        "object_cache_plugin",
        {
            Result.PARTIAL: (
                "The pinned Redis Object Cache plugin could not be installed, activated or "
                "connected. Read the run's journal on the server, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "object_cache_verify",
        {
            Result.PARTIAL: (
                "The object cache change did not verify: the site did not report the reviewed "
                "state afterwards. Read the run's journal, then prepare a new review that "
                "proposes only what remains."
            ),
        },
    ),
    ResultReason(
        "laravel_environment",
        {
            Result.PARTIAL: (
                "The site's environment step could not be written safely, so the cache change "
                "is partly applied and the site may still use its previous cache store. Run "
                "discovery, then prepare a new review of what remains."
            ),
        },
    ),
    ResultReason(
        "laravel_config",
        {
            Result.PARTIAL: (
                "The environment changed, but Laravel's cached configuration could not be "
                "rebuilt, so the site may still serve the previous configuration. Check the "
                "run's journal, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "laravel_worker",
        {
            Result.PARTIAL: (
                "The environment changed, but a running worker did not restart cleanly. The new "
                "configuration is written; check the worker and restart it from Settings."
            ),
        },
    ),
)
