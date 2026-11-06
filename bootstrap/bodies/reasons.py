"""The result reasons the bootstrap bodies can print (#495).

The host foundation's platform, privilege, headroom and precondition refusals are the
shared server-wide reasons declared in :mod:`operations.body_reasons`; only the
foundation's own download, installer, foreign-stack and Nix-shape causes are declared here.
"""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason

FOUNDATION_REASONS: Final = (
    ResultReason(
        "foundation",
        {
            Result.PARTIAL: (
                "The host setup stopped after changing part of the server, so Nix, the catalog "
                "profiles, Caddy or the journal may be partly applied and no rollback happens. "
                "Read the run's journal on the server, then prepare a new review of what "
                "remains."
            ),
        },
    ),
    ResultReason(
        "download",
        {
            Result.REFUSED: (
                "Barectl could not download the pinned Nix installer over HTTPS, so the host "
                "setup stopped before installing anything. Check the server's network access "
                "to releases.nixos.org, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "installer_digest",
        {
            Result.REFUSED: (
                "The downloaded Nix archive did not match the reviewed SHA-256 or did not "
                "contain the expected installer, so Barectl discarded it and stopped before "
                "installing anything. Check the server's download path, then prepare a new "
                "review."
            ),
        },
    ),
    ResultReason(
        "foreign_stack",
        {
            Result.REFUSED: (
                "Another web stack, an account or path Barectl did not create, or a service "
                "outside the supported web and SSH ports is present, so the host setup "
                "stopped. Remove the foreign stack through ordinary administration, then read "
                "the server again and prepare a new review."
            ),
        },
    ),
    ResultReason(
        "nix_incomplete",
        {
            Result.REFUSED: (
                "The existing Nix installation is incomplete or not the supported 2.35.2 "
                "daemon with a root-owned 0644 configuration, so the host setup stopped. "
                "Repair or remove the incomplete Nix shape through ordinary administration, "
                "then prepare a new review."
            ),
        },
    ),
)

CERTIFICATE_EMAIL_REASONS: Final = (
    ResultReason(
        "certificate_email",
        {
            Result.REFUSED: (
                "Barectl could not validate and publish the reviewed certificate contact "
                "email, so the main Caddy configuration was left as it was. Check the run's "
                "journal on the server, then prepare a new review."
            ),
            Result.PARTIAL: (
                "Barectl could not publish, reload and verify the reviewed certificate contact "
                "email. The previous main configuration was restored where it had been "
                "replaced. Check the run's journal on the server, then prepare a new review."
            ),
        },
    ),
)
