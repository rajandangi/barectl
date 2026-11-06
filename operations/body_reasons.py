"""Reasons several native bodies print for the same server-wide precondition (#495).

These are not the engine's admission prelude: a body prints them after the lock before its
own steps. They read the same wherever they appear, so they are declared once rather than
repeated per area, which also keeps one reason and outcome from acquiring two sentences.
"""

from typing import Final

from .models import Result
from .reasons import ResultReason, register_body

SHARED_REASONS: Final = (
    ResultReason(
        "precondition",
        {
            Result.REFUSED: (
                "Reviewed native evidence changed on the server before the run started, so "
                "it stopped before changing anything. Run discovery again, then prepare a new "
                "review."
            ),
        },
    ),
    ResultReason(
        "runtime_cache",
        {
            Result.REFUSED: (
                "The selected runtime's locked build is unavailable from the signed cache, so "
                "the run stopped before changing anything. Check the server's network access, "
                "then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "platform",
        {
            Result.REFUSED: (
                "The server is not Ubuntu 26.04 with the approved package and service "
                "versions, so the change stopped before changing anything. Check the server's "
                "standing, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "privilege",
        {
            Result.REFUSED: (
                "The SSH user is not root and is not authorized for this change without a "
                "password, so nothing ran. Connect as root or authorize the exact command "
                "through ordinary administration, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "headroom",
        {
            Result.REFUSED: (
                "The server does not have the free space or package-list room this change "
                "needs, so nothing changed. Free space or refresh the package lists, then "
                "prepare a new review."
            ),
        },
    ),
)

register_body("shared", SHARED_REASONS)
