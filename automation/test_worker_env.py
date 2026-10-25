"""The graceful worker restart an environment change uses (Phase C #393/#266)."""

from unittest import mock

from django.test import SimpleTestCase

from automation.bodies import worker_env


def completed(returncode: int = 0, stdout: str = "") -> mock.Mock:
    result = mock.Mock()
    result.returncode = returncode
    result.stdout = stdout
    return result


class WorkerRestartTests(SimpleTestCase):
    def test_no_enabled_worker_restarts_nothing(self) -> None:
        with mock.patch(
            "automation.bodies.worker_env.subprocess.run",
            return_value=completed(0, "disabled\n"),
        ) as run:
            self.assertEqual(worker_env.restart_workers("shop"), (False, True))
        self.assertEqual(run.call_count, 4)

    def test_only_enabled_workers_restart_gracefully(self) -> None:
        states = {"queue1": "enabled", "queue2": "disabled", "queue3": "static"}
        calls: list[list[str]] = []

        def run(argv: list[str], **_kwargs: object) -> mock.Mock:
            calls.append(argv)
            if argv[1] == "show":
                role = argv[-1].removeprefix("barectl-site-shop-").removesuffix(".service")
                return completed(0, states.get(role, "disabled") + "\n")
            return completed()

        with mock.patch("automation.bodies.worker_env.subprocess.run", side_effect=run):
            self.assertEqual(worker_env.restart_workers("shop"), (True, True))
        restarted = [argv[-1] for argv in calls if argv[1] == "restart"]
        self.assertEqual(
            restarted,
            [
                "barectl-site-shop-queue1.service",
                "barectl-site-shop-queue3.service",
            ],
        )

    def test_a_failed_restart_is_reported_and_stops(self) -> None:
        def run(argv: list[str], **_kwargs: object) -> mock.Mock:
            if argv[1] == "show":
                return completed(0, "enabled\n")
            return completed(1) if argv[-1].endswith("queue2.service") else completed()

        with mock.patch("automation.bodies.worker_env.subprocess.run", side_effect=run):
            self.assertEqual(worker_env.restart_workers("shop"), (True, False))
