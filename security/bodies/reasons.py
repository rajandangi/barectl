"""The result reasons the security bodies can print (#495).

Each change kind declares only its own body's reasons. The engine's admission reasons
(``evidence``, ``apt_active`` and the rest) and the shared server-wide preconditions
(``platform``, ``privilege``, ``headroom`` and ``precondition``) are declared once in
:mod:`operations.reasons` and :mod:`operations.body_reasons`.
"""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason

# The access-change fragments in operations/revert.py save a preimage and arm the put-back
# for both firewall and sign-in changes, so both kinds share this wording.
_REVERT_REASONS: Final = (
    ResultReason(
        "revert_preimage",
        {
            Result.REFUSED: (
                "Barectl could not save the previous access settings, so it stopped before "
                "changing anything. Check the run's journal on the server, then prepare again."
            ),
        },
    ),
    ResultReason(
        "revert_arm",
        {
            Result.REFUSED: (
                "Barectl could not arm the automatic put-back, so it stopped before changing "
                "anything."
            ),
        },
    ),
)

FIREWALL_REASONS: Final = (
    *_REVERT_REASONS,
    ResultReason(
        "firewall_ports",
        {
            Result.REFUSED: (
                "The server's SSH ports changed or no longer agree, so the run stopped before "
                "changing the firewall. Prepare a new review."
            ),
        },
    ),
    ResultReason(
        "firewall_outside",
        {
            Result.REFUSED: (
                "Another packet filter or a rule outside the supported shape appeared on the "
                "server, so the run stopped before changing the firewall."
            ),
        },
    ),
    ResultReason(
        "firewall_standard",
        {
            Result.REFUSED: (
                "The rule to remove is no longer an extra allowance, or the standard web and "
                "SSH allowances were asked for. The run stopped before changing the firewall. "
                "Prepare a new review."
            ),
        },
    ),
    ResultReason(
        "firewall_package",
        {
            Result.REFUSED: (
                "The firewall's package transaction did not match the reviewed one, so the run "
                "stopped before changing the firewall. Prepare a new review."
            ),
        },
    ),
    ResultReason(
        "firewall_apply",
        {
            Result.PARTIAL: (
                "The firewall change stopped partway. The server restores the previous "
                "firewall on its own; check the run's journal if it does not."
            ),
        },
    ),
    ResultReason(
        "firewall_verify",
        {
            Result.PARTIAL: (
                "The firewall did not read back as the reviewed change. The server restores "
                "the previous firewall on its own; check the run's journal if it does not."
            ),
        },
    ),
)

SIGN_IN_REASONS: Final = (
    *_REVERT_REASONS,
    ResultReason(
        "sign_in_syntax",
        {
            Result.REFUSED: (
                "OpenSSH rejected the existing configuration before Barectl changed anything."
            ),
            Result.PARTIAL: (
                "OpenSSH rejected the configuration. The server restores the previous sign-in "
                "settings on its own."
            ),
        },
    ),
    ResultReason(
        "sign_in_apply",
        {
            Result.REFUSED: (
                "Barectl could not prepare the sign-in file before changing the server."
            ),
            Result.PARTIAL: (
                "The sign-in change stopped partway. The server restores the previous settings "
                "on its own."
            ),
            Result.FAILED: (
                "The sign-in file write may have changed the server. The server is restoring "
                "the previous settings on its own."
            ),
        },
    ),
    ResultReason(
        "sign_in_reload",
        {
            Result.PARTIAL: (
                "SSH could not reload. The server restores the previous sign-in settings on "
                "its own."
            ),
        },
    ),
    ResultReason(
        "sign_in_verify",
        {
            Result.PARTIAL: (
                "The effective sign-in settings do not match the reviewed policy. The server "
                "restores the previous settings on its own."
            ),
        },
    ),
)

AUTOMATIC_UPDATES_REASONS: Final = (
    ResultReason(
        "automatic_updates_package",
        {
            Result.REFUSED: (
                "The reviewed unattended-upgrades package transaction did not match the "
                "server's resolved one, so Barectl stopped before further changes. Prepare a "
                "new review."
            ),
            Result.PARTIAL: (
                "The unattended-upgrades package did not read back as installed at the "
                "reviewed version after the change, so the run stopped partway and the "
                "automatic-update settings were not verified. Check the package through "
                "ordinary administration, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "automatic_updates_configure",
        {
            Result.PARTIAL: (
                "Ubuntu's automatic-update settings were not accepted. Read the server again "
                "before preparing a new review."
            ),
        },
    ),
    ResultReason(
        "automatic_updates_verify",
        {
            Result.PARTIAL: (
                "The automatic-update settings did not read back as reviewed. Read the server "
                "again before preparing a new review."
            ),
        },
    ),
    ResultReason(
        "automatic_updates_settings",
        {
            Result.PARTIAL: (
                "The server's customized automatic-update settings changed during the run, so "
                "Barectl stopped without overwriting them. Check them through ordinary "
                "administration."
            ),
        },
    ),
    ResultReason(
        "automatic_updates_failed",
        {
            Result.PARTIAL: (
                "The automatic-updates change stopped before reporting its outcome. Read the "
                "server again before preparing a new review."
            ),
        },
    ),
)

CHECK_UPDATES_REASONS: Final = (
    ResultReason(
        "updates_refresh",
        {
            Result.REFUSED: (
                "Ubuntu's package lists were not refreshed, so nothing was installed. Check "
                "the server's configured Ubuntu archive, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "updates_refresh_failed",
        {
            Result.PARTIAL: (
                "The package-list refresh stopped before reporting its outcome. Read the "
                "server again before preparing a new review."
            ),
        },
    ),
)

INSTALL_UPDATES_REASONS: Final = (
    ResultReason(
        "updates_conffile",
        {
            Result.REFUSED: (
                "A reviewed package's configuration file differs from the package's own copy, "
                "so Barectl stopped before changing packages. Restore or confirm it through "
                "ordinary administration, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "updates_hold",
        {
            Result.REFUSED: (
                "A reviewed package is now held with apt-mark hold, so Barectl stopped before "
                "changing packages. Release the hold through ordinary administration, then "
                "prepare a new review."
            ),
        },
    ),
    ResultReason(
        "updates_pending",
        {
            Result.REFUSED: (
                "Ubuntu's package database has an unfinished package state, so Barectl stopped "
                "before changing packages. Finish it through ordinary administration, then "
                "prepare a new review."
            ),
        },
    ),
    ResultReason(
        "updates_transaction",
        {
            Result.REFUSED: (
                "The server's resolved package transaction differs from the reviewed one, so "
                "Barectl stopped before changing packages. Check for updates and prepare a new "
                "review."
            ),
        },
    ),
    ResultReason(
        "updates_verify",
        {
            Result.REFUSED: (
                "The reviewed packages were installed, but a package version or the package "
                "database did not read back as expected. Read the server again before "
                "preparing a new review."
            ),
        },
    ),
    ResultReason(
        "updates_failed",
        {
            Result.PARTIAL: (
                "The updates change stopped before reporting its outcome. Read the server "
                "again before preparing a new review that proposes only what remains."
            ),
        },
    ),
)

RESTART_REASONS: Final = (
    ResultReason(
        "restart_work",
        {
            Result.REFUSED: (
                "A site backup, copy, check or cleanup, or Ubuntu's package maintenance, still "
                "had processes on the server, so the restart stopped before changing anything. "
                "Prepare a new review after it finishes."
            ),
        },
    ),
    ResultReason(
        "restart_evidence",
        {
            Result.REFUSED: (
                "The packages that asked for a restart changed after the review, so the "
                "restart stopped before changing anything. Read the server again and prepare a "
                "new review."
            ),
        },
    ),
    ResultReason(
        "restart_apply",
        {
            Result.PARTIAL: (
                "The restart stopped before asking the server to start again. Read the server "
                "through ordinary administration and prepare a new review."
            ),
        },
    ),
)
