"""The result reasons the automation bodies can print (#495, #504).

WordPress server cron, the Laravel scheduler and the Laravel queue workers stage the shared
site fragments and the automation unit helpers. Their reasons are declared here so a run
that stops names the start, unit, tick, run or environment step that stopped, instead of the
class sentence. The engine's admission reasons and the site vocabulary are declared
elsewhere and reused.
"""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason

AUTOMATION_START: Final = ResultReason(
    "automation_start",
    {
        Result.PARTIAL: (
            "The site's scheduled task did not start, so Barectl stopped before relying on "
            "it. Check the run's journal on the server, then prepare a new review."
        ),
    },
)

AUTOMATION_UNITS: Final = ResultReason(
    "automation_units",
    {
        Result.PARTIAL: (
            "Barectl could not install or remove the site's scheduled task units as reviewed, "
            "so the schedule may be partly installed. Check the run's journal on the server, "
            "then prepare a new review."
        ),
    },
)

AUTOMATION_CHANGE: Final = ResultReason(
    "automation",
    {
        Result.REFUSED: (
            "Barectl could not change the site's scheduled tasks, so nothing more was changed. "
            "Check the run's journal on the server, then prepare a new review."
        ),
        Result.FAILED: (
            "The change to the site's scheduled tasks stopped before reporting its outcome, so "
            "what changed is unknown and no rollback happens. Read the unit's journal on the "
            "server, then prepare a new review."
        ),
    },
)

SCHEDULE_REASONS: Final = (
    AUTOMATION_START,
    AUTOMATION_UNITS,
    AUTOMATION_CHANGE,
    ResultReason(
        "automation_tick",
        {
            Result.PARTIAL: (
                "The first scheduled run did not finish successfully within the reviewed wait, "
                "so Barectl did not hand cron over and page loads still run it. The server task "
                "stays installed and reports its next result; prepare a new review to finish."
            ),
        },
    ),
    ResultReason(
        "automation_configuration",
        {
            Result.PARTIAL: (
                "Barectl could not set or clear the site's cron setting in the private "
                "WordPress configuration. Check the run's journal, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "automation_site",
        {
            Result.REFUSED: (
                "The site's account, files or private configuration were not the reviewed "
                "ones, so the run stopped before changing anything. Run discovery again and "
                "prepare a new review."
            ),
        },
    ),
)

SCHEDULER_REASONS: Final = (
    AUTOMATION_START,
    AUTOMATION_UNITS,
    AUTOMATION_CHANGE,
    ResultReason(
        "automation_scheduler",
        {
            Result.REFUSED: (
                "The site's Laravel files, account or scheduler units were not the reviewed "
                "ones, so the run stopped before changing anything. Run discovery again and "
                "prepare a new review."
            ),
        },
    ),
    ResultReason(
        "automation_run",
        {
            Result.PARTIAL: (
                "The scheduler started one run, but it did not finish successfully. Nothing "
                "else was changed. Scheduled tasks shows the run's result; check the "
                "application and prepare a new review."
            ),
        },
    ),
    ResultReason(
        "automation_running",
        {
            Result.PARTIAL: (
                "The scheduler run is still going after the reviewed wait, so Barectl stopped "
                "waiting. It keeps running on the server; Scheduled tasks shows its result when "
                "it finishes."
            ),
        },
    ),
)

WORKER_REASONS: Final = (
    ResultReason(
        "queue_workers",
        {
            Result.REFUSED: (
                "Barectl could not change the site's queue workers, so the run stopped before "
                "changing them. Check the run's journal on the server, then prepare a new "
                "review."
            ),
        },
    ),
    ResultReason(
        "queue_workers_site",
        {
            Result.REFUSED: (
                "The site's account, current release or private files were not the reviewed "
                "ones, so the run stopped before changing anything. Run discovery again and "
                "prepare a new review."
            ),
        },
    ),
    ResultReason(
        "queue_workers_activation",
        {
            Result.REFUSED: (
                "The site's current release changed before the workers could start, so the run "
                "stopped without changing them. Deploy again, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "queue_workers_environment",
        {
            Result.REFUSED: (
                "Barectl could not write the site's queue-worker environment, including its "
                "retry interval, so no worker was started. Check the run's journal, then "
                "prepare a new review."
            ),
            Result.PARTIAL: (
                "Barectl wrote the site's retry interval but could not rebuild the queue-worker "
                "environment or prove the file, so no worker was started and the change is "
                "partly applied. Check the run's journal, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "queue_workers_start",
        {
            Result.PARTIAL: (
                "Barectl could not confirm that every queue worker process is running. Check "
                "the run's journal, then prepare a new review."
            ),
        },
    ),
    ResultReason(
        "queue_workers_stop",
        {
            Result.PARTIAL: (
                "Barectl could not confirm that every queue worker stopped. Check the run's "
                "journal, then prepare a new review."
            ),
        },
    ),
)
