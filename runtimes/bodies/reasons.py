"""The result reasons the runtime bodies can print (#495, #501).

``add.sh`` prints the realisation, configuration and start steps; the removal body prints
the two reasons that had no vocabulary at all, a runtime still in use and default commands
Barectl could not read. The configuration reason is also printed by the shared site bodies,
whose partial sentence is reused here so one reason never carries two wordings.
"""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason
from sites.bodies.reasons import SITE_REASONS

# The site vocabulary already owns this reason's partial sentence (#499). Reuse that text
# and add the refusal a runtime body prints before it changes anything.
_SITE_RUNTIME_CONFIG: Final = next(
    reason for reason in SITE_REASONS if reason.name == "runtime_config"
)
RUNTIME_CONFIG: Final = ResultReason(
    "runtime_config",
    {
        Result.REFUSED: (
            "The runtime configuration step could not be written or verified, so the run "
            "stopped before changing anything. Check the run's journal on the server, then "
            "prepare a new review."
        ),
        **_SITE_RUNTIME_CONFIG.sentences,
    },
)

RUNTIME_REALISE: Final = ResultReason(
    "runtime_realise",
    {
        Result.REFUSED: (
            "The runtime realisation step stopped before any profile moved: the server could "
            "not realise or verify the exact reviewed build. Read the run's journal on the "
            "server, then prepare a new review."
        ),
        Result.PARTIAL: (
            "The runtime realisation step stopped: the server could not realise the exact "
            "reviewed store path from the signed cache, so the run stopped partway. Read the "
            "run's journal on the server, then prepare a new review of what remains."
        ),
    },
)

ADD_REASONS: Final = (
    RUNTIME_CONFIG,
    RUNTIME_REALISE,
    ResultReason(
        "runtime_start",
        {
            Result.PARTIAL: (
                "The runtime start step stopped: the server could not enable and start the PHP "
                "master for this runtime, so the run stopped partway. Read the run's journal on "
                "the server, then prepare a new review of what remains."
            ),
        },
    ),
)

REMOVE_REASONS: Final = (
    RUNTIME_CONFIG,
    ResultReason(
        "runtime_in_use",
        {
            Result.REFUSED: (
                "The runtime is still in use, so the run stopped before removing anything. The "
                "server default commands still select it, or a site still uses it; change the "
                "server default to another runtime, or move the site to another runtime, then "
                "prepare a new review."
            ),
        },
    ),
    ResultReason(
        "defaults_unreadable",
        {
            Result.REFUSED: (
                "Barectl could not read the server's default PHP and Node commands, so it "
                "cannot prove this runtime is unused and stopped before removing anything. Run "
                "discovery again, check the default commands through ordinary administration, "
                "then prepare a new review."
            ),
        },
    ),
)

DEFAULTS_REASONS: Final = (RUNTIME_CONFIG,)

# The catalog update and revert stage the site PHP program, so their vocabulary is the
# shared site vocabulary plus the realisation step the update body names itself. The site
# runtime-configuration reason is replaced by RUNTIME_CONFIG, which carries both outcomes.
UPDATE_REASONS: Final = (
    *(reason for reason in SITE_REASONS if reason.name != "runtime_config"),
    RUNTIME_CONFIG,
    RUNTIME_REALISE,
)
