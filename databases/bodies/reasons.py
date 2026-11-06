"""The result reasons the database bodies can print (#495, #501).

The engine bodies print the package transaction and the shared restart that follows it.
The site-binding body prints each convention step it ran before it stopped, so the operator
knows whether the principal, database, privileges or schema exists.
"""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason

ENGINE_REASONS: Final = (
    ResultReason(
        "database_engine",
        {
            Result.REFUSED: (
                "The server's resolved package set differs from the reviewed one, so Barectl "
                "stopped before changing packages. Prepare a new review."
            ),
            Result.PARTIAL: (
                "The database engine step stopped after the package transaction began, so the "
                "engine may be partly installed or removed. Read the run's journal on the "
                "server, then prepare a new review of what remains."
            ),
        },
    ),
    ResultReason(
        "database_reload",
        {
            Result.PARTIAL: (
                "The database engine change was applied, but Barectl could not restart every "
                "running PHP master and site proxy, so discovery may report them outside "
                "supported settings until the server is restarted. Read the run's journal on "
                "the server, then prepare a new review."
            ),
        },
    ),
)

SITE_DATABASE_REASONS: Final = (
    ResultReason(
        "site_database",
        {
            Result.REFUSED: (
                "The site's own PHP master did not answer as the site user through its driver, "
                "or the database catalog changed, so Barectl stopped before creating the "
                "binding. Prepare a new review."
            ),
            Result.PARTIAL: (
                "The site database change stopped before it could apply every reviewed "
                "statement, so the binding is partly applied. Read the run's journal on the "
                "server, then prepare a new review of what remains."
            ),
        },
    ),
    ResultReason(
        "site_database_driver",
        {
            Result.REFUSED: (
                "The site's own PHP master did not load its driver or answer as the site user, "
                "so Barectl stopped before creating the binding. Check the site's PHP master, "
                "then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "site_database_principal",
        {
            Result.PARTIAL: (
                "The principal step of the site database change stopped: the engine did not "
                "accept the statement that creates the site's own login principal, so the "
                "binding is partly applied. Read the run's journal on the server, then prepare "
                "a new review of what remains."
            ),
        },
    ),
    ResultReason(
        "site_database_database",
        {
            Result.PARTIAL: (
                "The database step of the site database change stopped: the engine did not "
                "accept the statement that creates the site's own database, so the binding is "
                "partly applied. Read the run's journal on the server, then prepare a new "
                "review of what remains."
            ),
        },
    ),
    ResultReason(
        "site_database_privileges",
        {
            Result.PARTIAL: (
                "The privileges step of the site database change stopped: the engine did not "
                "accept the grant that limits the site's principal to its own database, so the "
                "binding is partly applied. Read the run's journal on the server, then prepare "
                "a new review of what remains."
            ),
        },
    ),
    ResultReason(
        "site_database_schema",
        {
            Result.PARTIAL: (
                "The schema step of the site database change stopped: the engine did not accept "
                "the statement that prepares the site's own schema, so the binding is partly "
                "applied. Read the run's journal on the server, then prepare a new review of "
                "what remains."
            ),
        },
    ),
    ResultReason(
        "site_database_after",
        {
            Result.PARTIAL: (
                "The proof step of the site database change stopped: the engine's catalog did "
                "not read back the reviewed principal, database, privileges and schema, so the "
                "binding is partly applied. Read the run's journal on the server, then prepare "
                "a new review of what remains."
            ),
        },
    ),
    ResultReason(
        "site_database_proof",
        {
            Result.PARTIAL: (
                "The proof step of the site database change stopped: PHP under the site's own "
                "master ran the reviewed probe but did not return the reviewed proof, so the "
                "binding is not proven. Read the run's journal on the server, then prepare a "
                "new review of what remains."
            ),
        },
    ),
    ResultReason(
        "site_database_probe",
        {
            Result.PARTIAL: (
                "The probe step of the site database change stopped: the reviewed binding was "
                "created, but Barectl could not remove the temporary probe file. Read the run's "
                "journal on the server, then prepare a new review."
            ),
        },
    ),
)
