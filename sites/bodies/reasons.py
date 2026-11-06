"""The result reasons the shared site bodies can print (#495).

Every site kind stages ``sites/bodies/common.py``, directly or through
``sites.observation.COMMON_SOURCE``, and most of them also stage one small entry-point
fragment. The entry-point fragments print no result line themselves, so their reasons are
the shared vocabulary declared here. The engine's own admission reasons (``unsafe_lock``,
``evidence`` and the rest) are declared once in :mod:`operations.reasons` and need not be
repeated.
"""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason

SITE_REASONS: Final = (
    ResultReason(
        "automation_fence",
        {
            Result.REFUSED: (
                "The site's background work did not stop within its budget, so the run "
                "stopped before changing anything and the site's background work stays "
                "paused. Check the run's journal, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "automation_restore",
        {
            Result.PARTIAL: (
                "The change verified, but Barectl could not prove the site's background work "
                "started again, so it stays paused and the change is partly applied. Check "
                "the run's journal, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "runtime_config",
        {
            Result.PARTIAL: (
                "The runtime configuration could not be changed or verified, so the run "
                "stopped partway. Read the run's journal on the server, then prepare a new "
                "review of what remains."
            ),
        },
    ),
    ResultReason(
        "site_client",
        {
            Result.PARTIAL: (
                "Barectl could not prove the site's cache PHP client after restarting its own "
                "master. Check the run's journal, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "site_caddy",
        {
            Result.PARTIAL: (
                "Barectl could not publish and verify the site's Caddy route, so the run "
                "stopped partway. Read the run's journal on the server, then prepare a new "
                "review of what remains."
            ),
        },
    ),
    ResultReason(
        "site_create",
        {
            Result.PARTIAL: (
                "The site was partly created: its account, folders or PHP master may be in "
                "place. Read the run's journal on the server, then prepare a new review of "
                "what remains."
            ),
        },
    ),
    ResultReason(
        "site_domains",
        {
            Result.REFUSED: (
                "The site's domains could not be prepared for the change, so nothing was "
                "published. Run discovery, check the names, then prepare a new review."
            ),
            Result.PARTIAL: (
                "The domains change stopped after publishing part of the site's names, so "
                "some names may serve and others may not. Read the run's journal on the "
                "server, then prepare a new review of what remains."
            ),
        },
    ),
    ResultReason(
        "readiness_publish",
        {
            Result.REFUSED: (
                "Barectl could not publish and verify the site's new readiness path, so the "
                "previous Caddy file is still serving. Check the run's journal, then prepare "
                "a new review."
            ),
        },
    ),
    ResultReason(
        "site_readiness",
        {
            Result.PARTIAL: (
                "The site did not answer its readiness path as required: the home page must "
                "answer below 500, and a path other than / must answer exactly 200. Check the "
                "site's code or choose another path, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "site_pool",
        {
            Result.PARTIAL: (
                "Barectl could not prove the site's new PHP settings after reloading its own "
                "master, so it restored the previous pool. Check the run's journal, then "
                "prepare a new review."
            ),
        },
    ),
)

# The removal body's own reasons (#500). Its shared preconditions are declared once in
# :mod:`operations.body_reasons`; ``automation_fence`` comes from ``SITE_REASONS``.
#
# A partial step names what is already gone and what remains: the removal runs gate, Caddy,
# services, configuration, database, certificate, files, accounts, verification in that
# order, and never rolls back.
REMOVAL_REASONS: Final = (
    ResultReason(
        "site_remove",
        {
            Result.REFUSED: (
                "The removal stopped before changing anything: its request was not a valid site "
                "removal, or a step before the first removal failed. Read the run's journal on "
                "the server, then prepare a new review."
            ),
            Result.PARTIAL: (
                "The removal stopped after changing the server at a step it did not name, so "
                "some of the site's resources may be gone and others may remain. Read the run's "
                "journal on the server, then prepare a new review of what remains."
            ),
        },
    ),
    ResultReason(
        "site_remove_evidence",
        {
            Result.REFUSED: (
                "Barectl could not read the site's native artifacts from the server, so the "
                "removal stopped before changing anything. Run discovery again, then prepare a "
                "new review."
            ),
        },
    ),
    ResultReason(
        "site_remove_caddy",
        {
            Result.REFUSED: (
                "Barectl could not make Caddy's disk and running configurations agree before "
                "removing the site's route, so the removal stopped after removing its backup "
                "units and before removing its Caddy configuration. The site's Caddy route "
                "still serves. Read the run's journal on the server, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "site_remove_database",
        {
            Result.PARTIAL: (
                "The database step stopped: Barectl could not drop or prove the site's "
                "database and principal. Its Caddy configuration, services, automation "
                "configuration and backup units are already removed, and its database still "
                "exists or could not be read. Read the run's journal on the server, then "
                "prepare a new review."
            ),
        },
    ),
    ResultReason(
        "site_remove_certificate",
        {
            Result.PARTIAL: (
                "The certificate step stopped: Barectl could not remove every stored "
                "certificate file for the site. Its Caddy configuration, services, "
                "configuration, database and backup units are already removed, but its "
                "certificate files, directory and accounts remain. Read the run's journal on "
                "the server, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "site_remove_accounts",
        {
            Result.PARTIAL: (
                "The accounts step stopped: Barectl could not remove the site's Linux accounts "
                "and groups. Its Caddy configuration, services, configuration, database, "
                "certificate and directory are already removed, but its accounts and groups "
                "remain. Read the run's journal on the server, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "site_remove_verify",
        {
            Result.PARTIAL: (
                "Final verification stopped: the reviewed resources were removed, but Barectl "
                "could not prove that nothing of the site remains. Read the run's journal on "
                "the server, then prepare a new review of what verification still sees."
            ),
        },
    ),
)
