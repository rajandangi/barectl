"""The result reasons the WordPress bodies can print (#495, #504).

Create, Reset password, Verify core and Edit settings stage the shared site fragments, the
WordPress convention and one entry-point body. Their reasons are declared here so a run that
stops names the database, gate, publish, create, password or checksum step that stopped,
instead of the class sentence. The engine's admission reasons, the site vocabulary and the
confidential-value reason are declared elsewhere and reused.
"""

from typing import Final

from operations.body_reasons import SETTINGS_SECRET
from operations.models import Result
from operations.reasons import ResultReason

WORDPRESS_SECRET: Final = ResultReason(
    "wordpress_secret",
    {
        Result.REFUSED: (
            "The confidential administrator password could not be used, so nothing changed. "
            "Prepare a new review and type the password again."
        ),
    },
)

CREATE_REASONS: Final = (
    WORDPRESS_SECRET,
    ResultReason(
        "wordpress_gate",
        {
            Result.REFUSED: (
                "Barectl could not establish the maintenance gate, so the run stopped before "
                "installing application files. Review again."
            ),
            Result.PARTIAL: (
                "Barectl created part of the site but could not establish the maintenance "
                "gate, so no application files were installed and the site is partly created. "
                "Read the run's journal on the server, then prepare a new review of what "
                "remains."
            ),
        },
    ),
    ResultReason(
        "wordpress_publish",
        {
            Result.PARTIAL: (
                "Barectl could not publish the verified site route, so the maintenance gate "
                "stays up. Read the run's journal and prepare a new review."
            ),
        },
    ),
    ResultReason(
        "wordpress_create",
        {
            Result.PARTIAL: (
                "The run stopped after changing the server, so the WordPress installation is "
                "partly applied and the maintenance gate stays up. Read the unit's journal on "
                "the server, then prepare a new review of what remains."
            ),
        },
    ),
)

ACTION_REASONS: Final = (
    WORDPRESS_SECRET,
    ResultReason(
        "wordpress_password",
        {
            Result.REFUSED: (
                "Barectl did not set a new password: WordPress has no user with that login, "
                "the user is not an administrator, or the value cannot be a password. The site "
                "is unchanged. Check the username and prepare a new review."
            ),
        },
    ),
    ResultReason(
        "wordpress_password_unverified",
        {
            Result.PARTIAL: (
                "The password update ran, but Barectl could not confirm it: WordPress did not "
                "store the new password, or its sign-in page did not accept it. The password "
                "may have changed, so try signing in before preparing another review."
            ),
        },
    ),
    ResultReason(
        "wordpress_checksums",
        {
            Result.REFUSED: (
                "Barectl compared the installed WordPress core with the official checksums for "
                "the reviewed version and found files that do not match. Nothing on the server "
                "changed. Inspect the site through ordinary administration and replace the "
                "affected files from the official release."
            ),
        },
    ),
    ResultReason(
        "wordpress_checksums_unavailable",
        {
            Result.REFUSED: (
                "Barectl could not compare the WordPress core with the official checksums: the "
                "checksum service could not be reached or WP-CLI could not read the site. "
                "Nothing on the server changed. Check the server's network access and prepare "
                "a new review."
            ),
        },
    ),
)

SETTINGS_REASONS: Final = (
    ResultReason(
        "wordpress_settings",
        {
            Result.REFUSED: (
                "The private WordPress configuration changed, is outside the supported grammar "
                "or could not be rewritten safely, so nothing changed. Run discovery and "
                "prepare a new review."
            ),
            Result.PARTIAL: (
                "The private WordPress configuration changed but did not read back as the "
                "reviewed one, so the change is partly applied. Run discovery, then prepare a "
                "new review of what remains."
            ),
        },
    ),
    SETTINGS_SECRET,
)
