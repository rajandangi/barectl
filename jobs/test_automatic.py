"""Automatic work rows in Jobs read Phase C's projection unchanged (#289).

Every expected value here is the wording the Phase C table documents, written out rather
than recomputed, so a change to either projection fails this test.
"""

from dataclasses import replace
from datetime import UTC, datetime
from typing import Final

from django.test import SimpleTestCase

from automation.observation import ObservedSchedule
from automation.status import ScheduleStatus
from automation.worker_observation import ObservedWorker
from automation.worker_status import WorkerStatus
from automation.workers import WorkerDefinition
from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED
from discovery.models import ObservationOutcome
from discovery.snapshot import Observation, ObservedCache, Snapshot
from servers.models import Server

from . import automatic
from .automatic import (
    OBJECT_CACHE,
    QUEUE_WORKER,
    SCHEDULED_TASK,
    automatic_work,
)

NOW: Final = datetime(2026, 11, 3, 9, 0, tzinfo=UTC)
NEXT_ELAPSE: Final = 1_762_000_000_000_000
SERVER: Final = Server(pk=7, name="Web", ssh_alias="web.example.com")

SCHEDULE_SENTENCES: Final = {
    ScheduleStatus.OFF: "Off",
    ScheduleStatus.WAITING: "On, waiting for its first run",
    ScheduleStatus.RUNNING: "A run is in progress",
    ScheduleStatus.SUCCEEDED: "On, the last run succeeded",
    ScheduleStatus.FAILED: "On, the last run failed",
    ScheduleStatus.TIMED_OUT: "On, the last run timed out",
    ScheduleStatus.SKIPPED: "On, a run took too long so the next one was skipped",
    ScheduleStatus.PAUSED: "Paused by an unfinished change",
    ScheduleStatus.OFF_MAINTENANCE: "Background work is off while the site is in maintenance",
    ScheduleStatus.NO_CRON: "No cron is running",
    ScheduleStatus.UNCONFIRMED: "Could not confirm",
}
SCHEDULE_ATTENTION: Final = {
    ScheduleStatus.FAILED,
    ScheduleStatus.TIMED_OUT,
    ScheduleStatus.SKIPPED,
    ScheduleStatus.PAUSED,
    ScheduleStatus.OFF_MAINTENANCE,
    ScheduleStatus.NO_CRON,
    ScheduleStatus.UNCONFIRMED,
}
WORKER_SENTENCES: Final = {
    WorkerStatus.OFF: "Off",
    WorkerStatus.RUNNING: "On, running",
    WorkerStatus.RESTARTING: "On, restarting after a crash",
    WorkerStatus.STOPPED_AFTER_CRASHES: "Stopped after repeated crashes",
    WorkerStatus.PAUSED: "Paused while a change finishes",
    WorkerStatus.OFF_MAINTENANCE: "Off while the site is in maintenance",
    WorkerStatus.UNCONFIRMED: "Could not confirm",
}
WORKER_ATTENTION: Final = {
    WorkerStatus.RESTARTING,
    WorkerStatus.STOPPED_AFTER_CRASHES,
    WorkerStatus.UNCONFIRMED,
}


def observed[T](value: T) -> Observation[T]:
    return Observation(ObservationOutcome.OBSERVED, (), "", value)


def schedule(
    status: ScheduleStatus,
    *,
    identifier: str = "alpha",
    role: str = "wpcron",
    next_elapse_us: int = NEXT_ELAPSE,
) -> ObservedSchedule:
    return ObservedSchedule(
        identifier=identifier,
        role=role,
        status=status,
        next_elapse_us=next_elapse_us,
        installed=status not in (ScheduleStatus.OFF, ScheduleStatus.NO_CRON),
        timer_active=status
        in (
            ScheduleStatus.WAITING,
            ScheduleStatus.SUCCEEDED,
            ScheduleStatus.FAILED,
            ScheduleStatus.TIMED_OUT,
            ScheduleStatus.SKIPPED,
        ),
        timer_enabled=status
        in (
            ScheduleStatus.WAITING,
            ScheduleStatus.SUCCEEDED,
            ScheduleStatus.FAILED,
            ScheduleStatus.TIMED_OUT,
            ScheduleStatus.SKIPPED,
        ),
    )


def worker(
    status: WorkerStatus,
    *,
    identifier: str = "beta",
) -> ObservedWorker:
    return ObservedWorker(
        identifier=identifier,
        status=status,
        definition=WorkerDefinition(("default",), 2, 60),
        processes=2,
        active_processes=2 if status == WorkerStatus.RUNNING else 0,
        installed=True,
        enabled=status != WorkerStatus.OFF,
    )


def cache(
    state: str,
    *,
    identifier: str = "alpha",
    problem: str = "",
) -> ObservedCache:
    return ObservedCache(identifier, state, 64 if state != "off" else None, problem)


def snapshot(
    *,
    schedules: tuple[ObservedSchedule, ...] = (),
    workers: tuple[ObservedWorker, ...] = (),
    caches: tuple[ObservedCache, ...] = (),
    automation: Observation[tuple[ObservedSchedule, ...]] | None = None,
    worker_observation: Observation[tuple[ObservedWorker, ...]] | None = None,
    cache_observation: Observation[tuple[ObservedCache, ...]] | None = None,
) -> Snapshot:
    sites = tuple(
        replace(site, application="wordpress") if site.identifier == "alpha" else site
        for site in COLLECTED.sites.value
    )
    collected = replace(
        COLLECTED,
        components=(),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        sites=observed(sites),
        automation=automation or observed(tuple(schedules)),
        workers=worker_observation or observed(tuple(workers)),
        cache=cache_observation or observed(tuple(caches)),
    )
    return Snapshot(collected, NOW, "web.example.com")


class ScheduleRowTests(SimpleTestCase):
    def test_every_scheduled_state_keeps_the_documented_sentence(self) -> None:
        for status, sentence in SCHEDULE_SENTENCES.items():
            with self.subTest(status=status):
                work = automatic_work(snapshot(schedules=(schedule(status),)), SERVER)
                (row,) = work.rows
                self.assertEqual(row.state, sentence)
                self.assertEqual(row.needs_attention, status in SCHEDULE_ATTENTION)

    def test_a_failed_run_needs_attention_with_the_overview_sentence(self) -> None:
        work = automatic_work(snapshot(schedules=(schedule(ScheduleStatus.FAILED),)), SERVER)
        (row,) = work.rows
        self.assertTrue(row.needs_attention)
        self.assertEqual(
            row.attention_sentence, "Scheduled tasks for alpha on, the last run failed."
        )

    def test_a_skipped_tick_needs_attention_with_the_overview_sentence(self) -> None:
        work = automatic_work(snapshot(schedules=(schedule(ScheduleStatus.SKIPPED),)), SERVER)
        (row,) = work.rows
        self.assertTrue(row.needs_attention)
        self.assertEqual(
            row.attention_sentence,
            "Scheduled tasks for alpha skipped a run because the previous run took "
            "longer than a minute.",
        )

    def test_a_deliberately_off_timer_is_off_and_not_flagged(self) -> None:
        work = automatic_work(snapshot(schedules=(schedule(ScheduleStatus.OFF),)), SERVER)
        (row,) = work.rows
        self.assertEqual(row.state, "Off")
        self.assertFalse(row.needs_attention)
        self.assertEqual(row.attention_sentence, "")

    def test_the_next_run_comes_only_from_systemds_next_elapse(self) -> None:
        work = automatic_work(
            snapshot(
                schedules=(
                    schedule(
                        ScheduleStatus.SUCCEEDED,
                        next_elapse_us=NEXT_ELAPSE,
                    ),
                )
            ),
            SERVER,
        )
        (row,) = work.rows
        self.assertEqual(row.next_run_at, datetime(2025, 11, 1, 12, 26, 40, tzinfo=UTC))
        self.assertFalse(row.next_run_unknown)

    def test_a_missing_next_elapse_is_unknown_and_never_invented(self) -> None:
        work = automatic_work(
            snapshot(schedules=(schedule(ScheduleStatus.SUCCEEDED, next_elapse_us=0),)),
            SERVER,
        )
        (row,) = work.rows
        self.assertIsNone(row.next_run_at)
        self.assertTrue(row.next_run_unknown)

    def test_a_scheduled_row_links_to_its_sites_settings_entry(self) -> None:
        work = automatic_work(snapshot(schedules=(schedule(ScheduleStatus.SUCCEEDED),)), SERVER)
        (row,) = work.rows
        self.assertEqual(row.link_url, "/servers/7/sites/alpha/settings/#scheduled-tasks")
        self.assertEqual(row.link_label, "Open scheduled tasks")

    def test_a_scheduled_row_carries_the_site_role_and_work_type(self) -> None:
        work = automatic_work(snapshot(schedules=(schedule(ScheduleStatus.SUCCEEDED),)), SERVER)
        (row,) = work.rows
        self.assertEqual(row.identifier, "alpha")
        self.assertEqual(row.role, "wpcron")
        self.assertEqual(row.work_type, SCHEDULED_TASK)
        self.assertEqual(
            row.units,
            (
                "barectl-site-alpha-wpcron.timer",
                "barectl-site-alpha-wpcron.service",
            ),
        )


class WorkerRowTests(SimpleTestCase):
    def test_every_worker_state_keeps_the_documented_sentence(self) -> None:
        for status, sentence in WORKER_SENTENCES.items():
            with self.subTest(status=status):
                work = automatic_work(snapshot(workers=(worker(status),)), SERVER)
                (row,) = work.rows
                self.assertEqual(row.state, sentence)
                self.assertEqual(row.needs_attention, status in WORKER_ATTENTION)

    def test_a_crash_looping_worker_needs_attention_with_the_overview_sentence(self) -> None:
        work = automatic_work(
            snapshot(workers=(worker(WorkerStatus.STOPPED_AFTER_CRASHES),)), SERVER
        )
        (row,) = work.rows
        self.assertTrue(row.needs_attention)
        self.assertEqual(
            row.attention_sentence,
            "Queue workers for beta stopped after repeated crashes.",
        )

    def test_a_worker_row_has_no_next_run_and_links_to_queue_workers(self) -> None:
        work = automatic_work(snapshot(workers=(worker(WorkerStatus.RUNNING),)), SERVER)
        (row,) = work.rows
        self.assertIsNone(row.next_run_at)
        self.assertFalse(row.next_run_unknown)
        self.assertEqual(row.identifier, "beta")
        self.assertEqual(row.role, "queue")
        self.assertEqual(row.work_type, QUEUE_WORKER)
        self.assertEqual(row.link_url, "/servers/7/sites/beta/settings/#queue-workers")


class CacheRowTests(SimpleTestCase):
    def test_an_on_cache_is_listed_and_links_to_the_object_cache_settings(self) -> None:
        work = automatic_work(snapshot(caches=(cache("on"),)), SERVER)
        (row,) = work.rows
        self.assertEqual(row.state, "On")
        self.assertFalse(row.needs_attention)
        self.assertEqual(row.work_type, OBJECT_CACHE)
        self.assertEqual(row.role, "cache")
        self.assertEqual(
            row.link_url,
            "/servers/7/sites/alpha/settings/#site-object-cache-heading",
        )

    def test_a_partly_on_cache_needs_attention_in_plain_words(self) -> None:
        work = automatic_work(
            snapshot(
                caches=(
                    cache(
                        "partial",
                        problem="The cache instance is not running.",
                    ),
                )
            ),
            SERVER,
        )
        (row,) = work.rows
        self.assertEqual(row.state, "Partly on")
        self.assertTrue(row.needs_attention)
        self.assertEqual(row.attention_sentence, "The object cache for alpha is only partly on.")
        self.assertIn("The cache instance is not running.", row.detail_lines[-1][1])

    def test_a_cache_outside_supported_settings_needs_attention(self) -> None:
        work = automatic_work(
            snapshot(
                caches=(
                    cache(
                        "unsupported",
                        problem="The cache instance runs outside the site's own account.",
                    ),
                )
            ),
            SERVER,
        )
        (row,) = work.rows
        self.assertEqual(row.state, "Outside supported settings")
        self.assertTrue(row.needs_attention)
        self.assertEqual(
            row.attention_sentence,
            "The object cache for alpha is outside supported settings.",
        )

    def test_an_off_cache_for_a_plain_site_is_not_listed(self) -> None:
        work = automatic_work(snapshot(caches=(cache("off", identifier="beta"),)), SERVER)
        self.assertEqual(work.rows, ())

    def test_an_off_cache_for_a_wordpress_site_is_off_and_not_flagged(self) -> None:
        work = automatic_work(snapshot(caches=(cache("off"),)), SERVER)
        (row,) = work.rows
        self.assertEqual(row.state, "Off")
        self.assertFalse(row.needs_attention)


class AutomaticCoverageTests(SimpleTestCase):
    def test_no_rows_and_no_warning_means_there_is_no_automatic_work(self) -> None:
        work = automatic_work(snapshot(), SERVER)
        self.assertEqual(work.rows, ())
        self.assertEqual(work.warnings, ())
        self.assertEqual(work.empty, automatic.NO_WORK)

    def test_an_unreadable_provider_keeps_its_warning_and_never_claims_none(self) -> None:
        unreadable = Observation[tuple[ObservedSchedule, ...]](
            ObservationOutcome.INACCESSIBLE,
            ("/etc/systemd/system",),
            "The scheduled tasks could not be read.",
            (),
        )
        work = automatic_work(snapshot(automation=unreadable), SERVER)
        self.assertEqual(work.rows, ())
        self.assertEqual(work.warnings, ("The scheduled tasks could not be read.",))
        self.assertEqual(work.empty, "")

    def test_one_unreadable_provider_keeps_the_other_providers_rows(self) -> None:
        unreadable = Observation[tuple[ObservedWorker, ...]](
            ObservationOutcome.INACCESSIBLE,
            ("/etc/systemd/system",),
            "The queue workers could not be read.",
            (),
        )
        work = automatic_work(
            snapshot(
                schedules=(schedule(ScheduleStatus.SUCCEEDED),),
                worker_observation=unreadable,
            ),
            SERVER,
        )
        self.assertEqual([row.work_type for row in work.rows], [SCHEDULED_TASK])
        self.assertEqual(work.warnings, ("The queue workers could not be read.",))
        self.assertEqual(work.empty, "")

    def test_rows_are_ordered_by_site_and_work_type(self) -> None:
        work = automatic_work(
            snapshot(
                schedules=(schedule(ScheduleStatus.SUCCEEDED),),
                workers=(worker(WorkerStatus.RUNNING),),
                caches=(cache("on", identifier="beta"),),
            ),
            SERVER,
        )
        self.assertEqual(
            [(row.identifier, row.work_type) for row in work.rows],
            [
                ("alpha", SCHEDULED_TASK),
                ("beta", QUEUE_WORKER),
                ("beta", OBJECT_CACHE),
            ],
        )


class SiteViewTests(SimpleTestCase):
    def test_site_and_work_type_are_structured_for_the_filters(self) -> None:
        work = automatic_work(
            snapshot(
                schedules=(schedule(ScheduleStatus.SUCCEEDED),),
                workers=(worker(WorkerStatus.RUNNING),),
                caches=(cache("on"),),
            ),
            SERVER,
        )
        self.assertEqual(
            [(row.identifier, row.role, row.work_type) for row in work.rows],
            [
                ("alpha", "wpcron", "scheduled_task"),
                ("alpha", "cache", "object_cache"),
                ("beta", "queue", "queue_worker"),
            ],
        )
