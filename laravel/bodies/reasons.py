"""The result reasons the Laravel bodies can print (#495, #504).

Create, Deploy, Roll back and Edit environment stage the shared site fragments, the Laravel
release primitives and one entry-point body. Their reasons are declared here so the run
screen names the source, disk, shared-files, fetch, composer, release, migration, readiness,
gate, environment, configuration or worker step that stopped, instead of the class sentence.
The engine's admission reasons and the site vocabulary are declared elsewhere and reused.
"""

from typing import Final

from operations.body_reasons import SETTINGS_SECRET
from operations.models import Result
from operations.reasons import ResultReason
from sites.bodies.reasons import SITE_REASONS

LARAVEL_COMMON_REASONS: Final = (
    ResultReason(
        "laravel_source",
        {
            Result.REFUSED: (
                "The site's repository or branch could not be resolved to a commit without "
                "fetch, so the run stopped before changing anything. Check the repository and "
                "branch, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "laravel_disk",
        {
            Result.REFUSED: (
                "The server lacks the free space the review stated, so the run stopped before "
                "changing anything. Free space on the server, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "laravel_shared",
        {
            Result.REFUSED: (
                "The site's shared environment, storage or cache is missing or unsafe, so the "
                "run stopped before switching code. The previous release is still serving."
            ),
            Result.PARTIAL: (
                "The new release could not be linked to the site's shared environment, storage "
                "or cache, so the run stopped before switching code. The previous release is "
                "still serving."
            ),
        },
    ),
    ResultReason(
        "laravel_fetch",
        {
            Result.REFUSED: (
                "The reviewed commit could not be fetched, so the run stopped before switching "
                "code. The previous release is still serving."
            ),
        },
    ),
    ResultReason(
        "laravel_composer",
        {
            Result.PARTIAL: (
                "The release's dependencies could not be installed in isolation, so the run "
                "stopped before switching code. The previous release is still serving."
            ),
        },
    ),
    ResultReason(
        "laravel_release",
        {
            Result.PARTIAL: (
                "The new release could not be published in the site's release layout, so the "
                "run stopped before switching code. The previous release is still serving."
            ),
        },
    ),
    ResultReason(
        "laravel_migrations",
        {
            Result.PARTIAL: (
                "A migration failed or the schema could not be verified, so Barectl kept the "
                "maintenance page up and did not open the new release or reactivate older "
                "code. Read the run's journal on the server, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "laravel_readiness",
        {
            Result.PARTIAL: (
                "The new release did not answer its readiness check, so it was not opened to "
                "visitors. The maintenance page is still up; read the run's journal and prepare "
                "a new review."
            ),
        },
    ),
    ResultReason(
        "laravel_gate",
        {
            Result.REFUSED: (
                "Barectl could not establish the maintenance page, so the run stopped before "
                "changing code. Review again."
            ),
            Result.PARTIAL: (
                "Barectl could not restore the site's open configuration after the readiness "
                "check, so the maintenance page may still be up. Read the run's journal on the "
                "server, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "release_absent",
        {
            Result.REFUSED: (
                "The release this change names is no longer retained on the server, so the run "
                "stopped before changing anything. Prepare a new review from the current "
                "release list."
            ),
        },
    ),
)

SETTINGS_STEP_REASONS: Final = (
    ResultReason(
        "laravel_environment",
        {
            Result.REFUSED: (
                "The site's environment file changed, is outside the supported layout or could "
                "not be rewritten safely, so nothing changed. Run discovery and prepare a new "
                "review."
            ),
            Result.PARTIAL: (
                "The environment was written but did not read back as the reviewed file, so the "
                "change is partly applied. Read the run's journal on the server, then prepare a "
                "new review of what remains."
            ),
        },
    ),
    ResultReason(
        "laravel_environment_managed",
        {
            Result.REFUSED: (
                "The selected environment key is managed by the site's object cache, so nothing "
                "changed. Change the object cache setting instead."
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

CREATE_REASONS: Final = (*SITE_REASONS, *LARAVEL_COMMON_REASONS)
DEPLOY_REASONS: Final = (*SITE_REASONS, *LARAVEL_COMMON_REASONS)
ROLLBACK_REASONS: Final = (*SITE_REASONS, *LARAVEL_COMMON_REASONS)
EDIT_REASONS: Final = (
    *SITE_REASONS,
    *LARAVEL_COMMON_REASONS,
    *SETTINGS_STEP_REASONS,
    SETTINGS_SECRET,
)
