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
