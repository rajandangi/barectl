"""The result reasons the run cleanup body can print (#495)."""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason

CLEANUP_REASONS: Final = (
    ResultReason(
        "cleanup",
        {
            Result.PARTIAL: (
                "The cleanup stopped partway: some finished barectl runs were cleared and "
                "others were not, so the change is partly applied and no rollback happens. "
                "Read the unit's journal on the server, then prepare a new review of what "
                "remains."
            ),
        },
    ),
)
