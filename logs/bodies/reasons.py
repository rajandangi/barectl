"""The result reasons the log rotation body can print (#495)."""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason

LOG_ROTATION_REASONS: Final = (
    ResultReason(
        "logrotate_missing",
        {
            Result.REFUSED: (
                "This server does not run logrotate, so the run stopped before changing "
                "anything. Install and enable it with ordinary administration, check the "
                "server again, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "rotation_invalid",
        {
            Result.REFUSED: (
                "logrotate refused the reviewed rotation file, so Barectl did not keep it. "
                "Check the run's journal, then prepare a new review."
            ),
        },
    ),
)

JOURNAL_RETENTION_REASONS: Final = (
    ResultReason(
        "journal_retention",
        {
            Result.REFUSED: (
                "The reviewed log retention setting could not be verified, so the server "
                "keeps its previous setting and nothing changed. Check the run's journal on "
                "the server, then prepare a new review."
            ),
            Result.PARTIAL: (
                "The reviewed log retention setting could not be verified, and Barectl could "
                "not restore the previous setting, so the change is partly applied. Check "
                "the server's journald configuration through ordinary administration before "
                "preparing a new review."
            ),
        },
    ),
)
