"""The queue-worker definition, its arithmetic and its supported hand-edit shape."""

from django.test import SimpleTestCase

from automation import convention, workers


def definition() -> workers.WorkerDefinition:
    return workers.WorkerDefinition(("default", "mail"), 2, 60)


class DefinitionTests(SimpleTestCase):
    def test_the_retry_interval_stays_above_the_job_and_below_the_stop_budget(self) -> None:
        value = definition()
        self.assertEqual(value.retry_after, 90)
        self.assertEqual(value.stop_seconds, 75)
        self.assertLess(value.timeout, value.retry_after)
        self.assertGreaterEqual(value.retry_after - value.timeout, 5)
        self.assertLess(value.timeout, value.stop_seconds)
        self.assertLess(value.stop_seconds, value.retry_after)

    def test_the_defaults_are_one_process_a_sixty_second_job_and_two_queues(self) -> None:
        parsed = workers.parse_definition("default, mail", 1, workers.DEFAULT_TIMEOUT)
        self.assertEqual(parsed, workers.WorkerDefinition(("default", "mail"), 1, 60))

    def test_queue_names_are_lowercase_letters_digits_hyphens_and_underscores(self) -> None:
        for value in ("default,mail", "default mail", " default , mail "):
            with self.subTest(value=value):
                self.assertEqual(workers.parse_queues(value), ("default", "mail"))
        for value in ("Default", "mail!", "a" * 33, "one,two,three,four,five,six,seven,eight,nine"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                workers.parse_queues(value)
        with self.assertRaises(ValueError):
            workers.parse_queues("default,default")

    def test_at_most_eight_queues_four_processes_and_a_timeout_of_thirty_to_nine_hundred(
        self,
    ) -> None:
        workers.parse_definition(",".join(f"q{index}" for index in range(8)), 4, 900)
        for queues, processes, timeout in (
            ("default", 0, 60),
            ("default", 5, 60),
            ("default", 1, 29),
            ("default", 1, 901),
            ("", 1, 60),
        ):
            with (
                self.subTest(queues=queues, processes=processes, timeout=timeout),
                self.assertRaises(ValueError),
            ):
                workers.parse_definition(queues, processes, timeout)

    def test_a_stored_definition_round_trips_and_a_forged_one_is_refused(self) -> None:
        stored = definition().document()
        self.assertEqual(workers.checked_definition(stored), definition())
        for forged in (
            {**stored, "timeout": 29},
            {**stored, "processes": 5},
            {**stored, "queues": ["Bad"]},
            {"queues": ["default"], "processes": 1},
            {**stored, "queues": "default"},
        ):
            with self.subTest(forged=forged), self.assertRaises(ValueError):
                workers.checked_definition(forged)


class RenderingTests(SimpleTestCase):
    def test_every_process_is_an_exec_service_in_the_site_identity_and_slice(self) -> None:
        text = workers.render_worker_service("shop", 2, definition())
        for line in (
            "Type=exec\n",
            "User=sshop\n",
            "Group=sshop\n",
            "WorkingDirectory=/var/www/shop/current\n",
            "Slice=barectl-site-shop.slice\n",
            "Restart=always\n",
            "RestartSec=5s\n",
            "StartLimitIntervalSec=60s\n",
            "StartLimitBurst=5\n",
            "KillMode=control-group\n",
            "TimeoutStopSec=75s\n",
            "WantedBy=multi-user.target\n",
        ):
            self.assertIn(line, text)
        self.assertIn(
            "ExecStart=/var/www/shop/bin/php artisan queue:work database "
            "--queue=default,mail --sleep=3 --tries=3 --max-time=3600 --timeout=60\n",
            text,
        )
        self.assertNotIn("queue:restart", text)
        self.assertLess(text.index("[Unit]"), text.index("StartLimitIntervalSec"))
        self.assertLess(text.index("StartLimitBurst"), text.index("[Service]"))

    def test_the_slice_and_every_reviewed_process_are_rendered(self) -> None:
        units = workers.render_worker_units("shop", definition())
        self.assertEqual(
            [name for _kind, name, _text in units],
            [
                "barectl-site-shop.slice",
                "barectl-site-shop-queue1.service",
                "barectl-site-shop-queue2.service",
            ],
        )
        self.assertEqual(
            set(workers.expected_units("shop", definition())), {"slice", "queue1", "queue2"}
        )

    def test_the_stop_budget_follows_the_timeout_without_changing_the_other_limits(self) -> None:
        text = workers.render_worker_service(
            "shop", 1, workers.WorkerDefinition(("default",), 1, 900)
        )
        self.assertIn("TimeoutStopSec=915s\n", text)
        self.assertIn("--timeout=900\n", text)


class ShapeTests(SimpleTestCase):
    def units(self, value: workers.WorkerDefinition) -> tuple[tuple[str, str, str], ...]:
        return tuple(workers.render_worker_units("shop", value))

    def test_a_rendered_worker_reads_back_as_the_same_definition(self) -> None:
        shape = workers.read_worker_shape("shop", self.units(definition()))
        self.assertEqual(shape.problems, ())
        self.assertEqual(shape.definition, definition())
        self.assertEqual(shape.processes, 2)
        self.assertEqual(set(shape.digests), {"slice", "queue1", "queue2"})

    def test_a_hand_edited_queue_list_process_count_or_timeout_in_bounds_is_adopted(self) -> None:
        edited = workers.WorkerDefinition(("critical", "mail", "bulk"), 1, 240)
        shape = workers.read_worker_shape("shop", self.units(edited))
        self.assertEqual(shape.problems, ())
        self.assertEqual(shape.definition, edited)

        single = workers.WorkerDefinition(("default",), 1, 60)
        extra = (
            *self.units(single),
            *workers.render_worker_units("shop", workers.WorkerDefinition(("default",), 2, 60))[2:],
        )
        shape = workers.read_worker_shape("shop", extra)
        self.assertEqual(shape.problems, ())
        self.assertEqual(shape.definition, workers.WorkerDefinition(("default",), 2, 60))

    def test_a_changed_command_account_restart_policy_or_unknown_setting_is_reported(self) -> None:
        text = workers.render_worker_service("shop", 1, definition())
        for old, new in (
            ("--sleep=3", "--sleep=0"),
            ("--timeout=60", "--timeout=5"),
            ("User=sshop", "User=root"),
            ("Restart=always", "Restart=no"),
            ("TimeoutStopSec=75s", "TimeoutStopSec=60s"),
            ("WantedBy=multi-user.target", "WantedBy=default.target"),
        ):
            with self.subTest(new=new):
                edited = text.replace(old, new)
                shape = workers.read_worker_shape(
                    "shop",
                    (
                        ("slice", convention.slice_name("shop"), convention.render_slice("shop")),
                        ("service", convention.service_name("shop", "queue1"), edited),
                    ),
                )
                self.assertIsNone(shape.definition)
                self.assertTrue(shape.problems)

    def test_a_gap_in_process_numbering_is_reported_once(self) -> None:
        shape = workers.read_worker_shape(
            "shop",
            (
                ("slice", convention.slice_name("shop"), convention.render_slice("shop")),
                (
                    "service",
                    convention.service_name("shop", "queue2"),
                    workers.render_worker_service("shop", 2, definition()),
                ),
            ),
        )
        self.assertIsNone(shape.definition)
        self.assertIn("not numbered from one", shape.problems[0])

    def test_a_timer_for_a_worker_is_reported(self) -> None:
        shape = workers.read_worker_shape(
            "shop",
            (
                *self.units(workers.WorkerDefinition(("default",), 1, 60)),
                (
                    "timer",
                    convention.timer_name("shop", "queue1"),
                    "[Timer]\nOnCalendar=*-*-* *:*:00\nUnit=barectl-site-shop-queue1.service\n",
                ),
            ),
        )
        self.assertIsNone(shape.definition)
        self.assertTrue(shape.problems)
