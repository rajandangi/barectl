"""The one status projection for every state a site's scheduled work can be in."""

from django.test import SimpleTestCase

from automation.status import (
    ATTENTION_STATUSES,
    STATUS_SENTENCE,
    ScheduleEvidence,
    ScheduleStatus,
    attention_problem,
    project,
    spanned_a_calendar_elapse,
)

MINUTE = 60_000_000


def evidence(
    *,
    readable: bool = True,
    installed: bool = False,
    timer_active: bool = False,
    timer_enabled: bool = False,
    service_active: bool = False,
    masked: bool = False,
    result: str = "",
    exec_status: int = 0,
    last_start_us: int = 0,
    last_exit_us: int = 0,
    disable_wp_cron: str = "",
    duplicate: str = "",
    gate: bool = False,
    problems: tuple[str, ...] = (),
) -> ScheduleEvidence:
    return ScheduleEvidence(
        identifier="shop",
        readable=readable,
        installed=installed,
        timer_active=timer_active,
        timer_enabled=timer_enabled,
        service_active=service_active,
        masked=masked,
        result=result,
        exec_status=exec_status,
        last_start_us=last_start_us,
        last_exit_us=last_exit_us,
        disable_wp_cron=disable_wp_cron,
        duplicate=duplicate,
        gate=gate,
        problems=problems,
    )


class ProjectionTests(SimpleTestCase):
    def test_off_is_a_deliberate_choice_and_not_an_alarm(self) -> None:
        status = project(evidence())
        self.assertEqual(status, ScheduleStatus.OFF)
        self.assertNotIn(status, ATTENTION_STATUSES)
        self.assertEqual(STATUS_SENTENCE[status], "Off")

    def test_an_armed_timer_that_has_not_run_waits(self) -> None:
        status = project(evidence(installed=True, timer_active=True, timer_enabled=True))
        self.assertEqual(status, ScheduleStatus.WAITING)

    def test_an_active_run_is_running(self) -> None:
        status = project(
            evidence(
                installed=True,
                timer_active=True,
                timer_enabled=True,
                service_active=True,
                result="success",
            )
        )
        self.assertEqual(status, ScheduleStatus.RUNNING)

    def test_a_successful_last_run_and_a_failed_one_stay_distinct(self) -> None:
        succeeded = project(
            evidence(
                installed=True,
                timer_active=True,
                timer_enabled=True,
                result="success",
                last_start_us=10 * MINUTE,
                last_exit_us=10 * MINUTE + 5_000_000,
            )
        )
        failed = project(
            evidence(
                installed=True,
                timer_active=True,
                timer_enabled=True,
                result="exit-code",
                exec_status=1,
                last_start_us=10 * MINUTE,
                last_exit_us=10 * MINUTE + 5_000_000,
            )
        )
        self.assertEqual(succeeded, ScheduleStatus.SUCCEEDED)
        self.assertEqual(failed, ScheduleStatus.FAILED)

    def test_a_run_stopped_by_its_limit_times_out_and_is_an_alarm(self) -> None:
        status = project(evidence(timer_active=True, timer_enabled=True, result="timeout"))
        self.assertEqual(status, ScheduleStatus.TIMED_OUT)
        self.assertIn(status, ATTENTION_STATUSES)

    def test_a_tick_that_elapsed_during_a_run_reads_skipped_not_succeeded(self) -> None:
        run = evidence(
            timer_active=True,
            timer_enabled=True,
            result="success",
            last_start_us=10 * MINUTE,
            last_exit_us=12 * MINUTE,
        )
        self.assertTrue(spanned_a_calendar_elapse(run))
        self.assertEqual(project(run), ScheduleStatus.SKIPPED)
        self.assertIn(
            "skipped a run",
            attention_problem(run, ScheduleStatus.SKIPPED),
        )

    def test_a_run_inside_one_minute_is_never_skipped(self) -> None:
        run = evidence(
            timer_active=True,
            timer_enabled=True,
            result="success",
            last_start_us=10 * MINUTE + 1,
            last_exit_us=10 * MINUTE + 59 * 1_000_000,
        )
        self.assertFalse(spanned_a_calendar_elapse(run))
        self.assertEqual(project(run), ScheduleStatus.SUCCEEDED)

    def test_a_long_failed_run_reports_the_failure_before_the_skip(self) -> None:
        status = project(
            evidence(
                timer_active=True,
                timer_enabled=True,
                result="exit-code",
                last_start_us=10 * MINUTE,
                last_exit_us=12 * MINUTE,
            )
        )
        self.assertEqual(status, ScheduleStatus.FAILED)

    def test_a_masked_unit_is_paused_by_an_unfinished_change(self) -> None:
        self.assertEqual(
            project(evidence(installed=True, masked=True, timer_enabled=True)),
            ScheduleStatus.PAUSED,
        )

    def test_a_gate_with_boot_activation_off_reads_off_during_maintenance(self) -> None:
        self.assertEqual(
            project(evidence(installed=True, gate=True, timer_enabled=False)),
            ScheduleStatus.OFF_MAINTENANCE,
        )

    def test_a_constant_set_by_hand_with_no_task_reads_no_cron_running(self) -> None:
        status = project(evidence(disable_wp_cron="true"))
        self.assertEqual(status, ScheduleStatus.NO_CRON)
        self.assertEqual(STATUS_SENTENCE[status], "No cron is running")
        self.assertIn("no server cron", attention_problem(evidence(disable_wp_cron="true"), status))

    def test_an_unreadable_answer_is_never_success(self) -> None:
        status = project(evidence(readable=False, result="success", last_exit_us=MINUTE))
        self.assertEqual(status, ScheduleStatus.UNCONFIRMED)
        self.assertIn(status, ATTENTION_STATUSES)
        self.assertIn("could not confirm", attention_problem(evidence(readable=False), status))

    def test_every_status_has_a_plain_sentence(self) -> None:
        self.assertEqual(set(STATUS_SENTENCE), set(ScheduleStatus))
