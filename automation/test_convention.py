"""The automation convention: names, paths, rendered units and supported hand edits."""

from django.test import SimpleTestCase

from automation import convention


class NameTests(SimpleTestCase):
    def test_one_site_has_one_slice_and_one_service_and_timer_per_role(self) -> None:
        self.assertEqual(convention.slice_name("shop"), "barectl-site-shop.slice")
        self.assertEqual(
            convention.service_name("shop", "wpcron"), "barectl-site-shop-wpcron.service"
        )
        self.assertEqual(convention.timer_name("shop", "wpcron"), "barectl-site-shop-wpcron.timer")
        self.assertEqual(
            convention.unit_file("shop", "wpcron", "service"),
            "/etc/systemd/system/barectl-site-shop-wpcron.service",
        )
        self.assertEqual(convention.account("shop"), "sshop")
        self.assertEqual(convention.site_directory("shop"), "/var/www/shop")

    def test_an_invalid_identifier_is_refused(self) -> None:
        for identifier in ("", "Shop", "s", "shop-1", "a" * 25):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                convention.slice_name(identifier)

    def test_a_role_is_read_back_from_the_unit_name(self) -> None:
        self.assertEqual(convention.role_of("barectl-site-shop-wpcron.timer", "shop"), "wpcron")
        self.assertIsNone(convention.role_of("barectl-apply-" + "a" * 32 + ".service", "shop"))
        self.assertIsNone(convention.role_of("barectl-site-other-wpcron.timer", "shop"))

    def test_every_reviewed_queue_process_has_one_role(self) -> None:
        self.assertEqual(
            [convention.queue_role(index) for index in (1, 2, 3, 4)],
            ["queue1", "queue2", "queue3", "queue4"],
        )
        for index in (0, 5):
            with self.subTest(index=index), self.assertRaises(ValueError):
                convention.queue_role(index)

    def test_a_queue_role_is_recognized_only_inside_the_reviewed_bound(self) -> None:
        self.assertEqual(convention.queue_index("queue1"), 1)
        self.assertEqual(convention.queue_index("queue4"), 4)
        for role in ("queue", "queue0", "queue5", "queue01", "wpcron", "queuex"):
            with self.subTest(role=role):
                self.assertIsNone(convention.queue_index(role))

    def test_queue_roles_are_resolved_from_installed_unit_names_in_process_order(self) -> None:
        names = (
            "/etc/systemd/system/barectl-site-shop-queue3.service",
            "barectl-site-shop-wpcron.service",
            "barectl-site-shop-queue1.service",
            "barectl-site-other-queue2.service",
            "barectl-site-shop-queue9.service",
            "barectl-site-shop-queue2.timer",
        )
        self.assertEqual(convention.queue_roles(names, "shop"), ("queue1", "queue3"))


class RenderingTests(SimpleTestCase):
    def test_the_service_is_a_oneshot_in_the_site_identity_with_its_own_limit(self) -> None:
        text = convention.render_service("shop", "wpcron")
        self.assertIn("Type=oneshot\n", text)
        self.assertIn("User=sshop\n", text)
        self.assertIn("Group=sshop\n", text)
        self.assertIn("WorkingDirectory=/var/www/shop/current\n", text)
        self.assertIn("Slice=barectl-site-shop.slice\n", text)
        self.assertIn("TimeoutStartSec=15min\n", text)
        self.assertIn("KillMode=control-group\n", text)
        self.assertIn(
            "ExecStart=/var/www/shop/bin/wp --path=/var/www/shop/current/public "
            "cron event run --due-now\n",
            text,
        )
        self.assertNotIn("RuntimeMaxSec", text)

    def test_the_laravel_scheduler_uses_the_site_php_and_current_release(self) -> None:
        text = convention.render_service("shop", "schedule")
        self.assertIn("Type=oneshot\n", text)
        self.assertIn("User=sshop\n", text)
        self.assertIn("WorkingDirectory=/var/www/shop/current\n", text)
        self.assertIn("TimeoutStartSec=1h\n", text)
        self.assertIn("KillMode=control-group\n", text)
        self.assertIn(
            "ExecStart=/var/www/shop/bin/php /var/www/shop/current/artisan schedule:run\n",
            text,
        )
        self.assertNotIn("RuntimeMaxSec", text)

    def test_the_timer_runs_every_minute_without_catch_up_or_delay(self) -> None:
        text = convention.render_timer("shop", "wpcron")
        for line in (
            "OnCalendar=*-*-* *:*:00\n",
            "AccuracySec=1s\n",
            "RandomizedDelaySec=0\n",
            "Persistent=false\n",
            "DeferReactivation=yes\n",
            "Unit=barectl-site-shop-wpcron.service\n",
            "WantedBy=timers.target\n",
        ):
            self.assertIn(line, text)

    def test_the_slice_is_an_empty_root_container_of_its_own(self) -> None:
        self.assertEqual(
            convention.render_slice("shop"),
            "[Unit]\nDescription=Barectl background work for shop\n\n[Slice]\n",
        )


class ShapeTests(SimpleTestCase):
    def parse(self, kind: str, text: str) -> convention.UnitShape:
        name = {
            "slice": convention.slice_name("shop"),
            "service": convention.service_name("shop", "wpcron"),
            "timer": convention.timer_name("shop", "wpcron"),
        }[kind]
        return convention.parse_unit(name, text, "shop", "wpcron", kind)

    def test_a_comment_and_a_reordered_directive_are_supported_hand_edits(self) -> None:
        text = convention.render_service("shop", "wpcron")
        reordered = "\n".join(
            [
                "# kept by the operator",
                "[Service]",
                "Type=oneshot",
                "User=sshop",
                "Group=sshop",
                "WorkingDirectory=/var/www/shop/current",
                "Slice=barectl-site-shop.slice",
                "TimeoutStartSec=15min",
                "KillMode=control-group",
                (
                    "ExecStart=/var/www/shop/bin/wp "
                    "--path=/var/www/shop/current/public cron event run --due-now"
                ),
                "",
                "[Unit]",
                "Description=Barectl wpcron for shop",
                "ConditionPathIsDirectory=/var/www/shop/current",
                "ConditionFileIsExecutable=/var/www/shop/bin/wp",
                "",
            ]
        )
        self.assertTrue(self.parse("service", text).supported)
        shape = self.parse("service", reordered)
        self.assertTrue(shape.supported, shape.problem)

    def test_a_changed_command_or_account_is_reported_not_adopted(self) -> None:
        for old, new in (
            (
                (
                    "ExecStart=/var/www/shop/bin/wp "
                    "--path=/var/www/shop/current/public cron event run --due-now"
                ),
                "ExecStart=/bin/true",
            ),
            ("User=sshop", "User=root"),
            ("TimeoutStartSec=15min", "TimeoutStartSec=1h"),
        ):
            with self.subTest(new=new):
                shape = self.parse(
                    "service", convention.render_service("shop", "wpcron").replace(old, new)
                )
                self.assertFalse(shape.supported)
                self.assertTrue(shape.problem)

    def test_an_unknown_directive_is_reported_once(self) -> None:
        shape = self.parse(
            "timer",
            convention.render_timer("shop", "wpcron") + "RandomizedDelaySec=30s\n",
        )
        self.assertFalse(shape.supported)
        self.assertIn("RandomizedDelaySec", shape.problem)

    def test_a_missing_required_directive_is_reported(self) -> None:
        shape = self.parse(
            "timer",
            convention.render_timer("shop", "wpcron").replace(
                "Unit=barectl-site-shop-wpcron.service\n", ""
            ),
        )
        self.assertFalse(shape.supported)

    def test_another_units_name_is_never_this_sites_shape(self) -> None:
        shape = convention.parse_unit(
            "barectl-site-other-wpcron.service",
            convention.render_service("shop", "wpcron"),
            "shop",
            "wpcron",
            "service",
        )
        self.assertFalse(shape.supported)
