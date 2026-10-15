import json
from unittest import TestCase

from sites.bodies.site_fpm import sfp_status_idle


class SiteFpmStatusTests(TestCase):
    def response(self, *, state: str = "Idle", pids: tuple[int, ...] = (101, 102)) -> str:
        return "Content-type: application/json\r\n\r\n" + json.dumps(
            {
                "pool": "alpha",
                "process manager": "static",
                "total processes": 2,
                "idle processes": 2 if state == "Idle" else 1,
                "active processes": 0 if state == "Idle" else 1,
                "processes": [{"pid": pid, "state": state} for pid in pids],
            }
        )

    def test_complete_idle_inventory_permits_cleanup(self) -> None:
        self.assertTrue(sfp_status_idle(self.response(), "alpha", [101, 102]))

    def test_post_response_finishing_work_prevents_cleanup(self) -> None:
        self.assertFalse(sfp_status_idle(self.response(state="Finishing"), "alpha", [101, 102]))

    def test_missing_duplicate_or_replaced_worker_prevents_cleanup(self) -> None:
        for pids in ((101,), (101, 101), (101, 103)):
            with self.subTest(pids=pids):
                self.assertFalse(sfp_status_idle(self.response(pids=pids), "alpha", [101, 102]))

    def test_other_pool_and_failed_or_incomplete_response_prevent_cleanup(self) -> None:
        for response in (
            self.response().replace('"alpha"', '"beta"'),
            "Status: 503 Service Unavailable\r\n" + self.response(),
            self.response()[:-1],
            self.response().replace('"pid": 101', '"pid": true'),
        ):
            with self.subTest(response=response):
                self.assertFalse(sfp_status_idle(response, "alpha", [101, 102]))


class SiteFpmInventoryTests(TestCase):
    def process(self, pid: int, parent: int, title: str, uid: int = 1201) -> dict[str, object]:
        return {"pid": pid, "parent": parent, "title": title, "uid": [uid] * 4, "gid": [uid] * 4}

    def test_missing_master_cannot_attest_complete_inventory(self) -> None:
        from unittest.mock import patch

        from sites.bodies.site_fpm import sfp_classify

        with patch("sites.bodies.site_fpm.pwd.getpwnam") as user:
            user.return_value.pw_uid = user.return_value.pw_gid = 1201
            self.assertIsNone(
                sfp_classify(
                    "alpha",
                    100,
                    [
                        self.process(101, 100, "php-fpm: pool alpha"),
                        self.process(102, 100, "php-fpm: pool alpha"),
                    ],
                )
            )

    def test_extra_or_reparented_application_work_prevents_cleanup(self) -> None:
        from unittest.mock import patch

        from sites.bodies.site_fpm import sfp_classify

        master = self.process(100, 1, "php-fpm: master process", 0)
        children = [
            self.process(101, 100, "php-fpm: pool alpha"),
            self.process(102, 100, "php-fpm: pool alpha"),
        ]
        with patch("sites.bodies.site_fpm.pwd.getpwnam") as user:
            user.return_value.pw_uid = user.return_value.pw_gid = 1201
            self.assertIsNotNone(sfp_classify("alpha", 100, [master, *children]))
            for extra in (
                self.process(103, 101, "php script.php"),
                self.process(103, 1, "php-fpm: pool alpha"),
                self.process(103, 100, "php-fpm: pool foreign"),
                self.process(103, 100, "php-fpm: pool alpha_status", 1202),
                None,
            ):
                with self.subTest(extra=extra):
                    self.assertIsNone(sfp_classify("alpha", 100, [master, *children, extra]))


class SiteFpmExecutionTests(TestCase):
    def context(self) -> dict[str, object]:
        executable = "/nix/var/nix/profiles/barectl/php84/bin/php-fpm"
        base = "/etc/php-fpm/sites/alpha/php84"
        return {
            "MainPID": 100,
            "Type": "notify",
            "ExecMainStartTimestamp": 1000,
            "ExecMainStartTimestampMonotonic": 100,
            "ExecStart": [
                [
                    executable,
                    [executable, "-F", "-y", base + "/php-fpm.conf", "-c", base + "/php.ini"],
                    False,
                    1000,
                    100,
                    0,
                    0,
                    100,
                    0,
                    0,
                ]
            ],
            "ExecStartPost": [
                [
                    "/usr/bin/chmod",
                    ["/usr/bin/chmod", "0600", "/run/php-fpm/sites/alpha/php84/status/listen.sock"],
                    False,
                    1100,
                    110,
                    1200,
                    120,
                    200,
                    1,
                    0,
                ]
            ],
            "ExecReload": [],
            "Environment": [],
            "EnvironmentFiles": [],
            "PassEnvironment": [],
            "UnsetEnvironment": [],
            "DropInPaths": [],
            "KillSignal": 3,
            "TimeoutStopUSec": 18446744073709551615,
            "SendSIGKILL": False,
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "FragmentPath": "/etc/systemd/system/php-fpm-site-php84@.service",
        }

    def test_exact_executed_foreground_notify_service_is_supported(self) -> None:
        from sites.bodies.site_fpm import sfp_execution

        self.assertTrue(sfp_execution("alpha", "php84", self.context()))

    def test_overridden_environment_reload_force_stop_or_wrong_generation_refuses(self) -> None:
        from sites.bodies.site_fpm import sfp_execution

        for key, value in (
            ("Environment", ["PHP_INI_SCAN_DIR=/foreign"]),
            ("DropInPaths", ["/etc/systemd/system/foreign.conf"]),
            ("ExecReload", [["/bin/kill"]]),
            ("MainPID", 101),
            ("Type", "simple"),
            ("SendSIGKILL", True),
            ("TimeoutStopUSec", 1000000),
        ):
            with self.subTest(key=key):
                self.assertFalse(sfp_execution("alpha", "php84", self.context() | {key: value}))


class SiteFpmSocketTests(TestCase):
    def test_private_socket_group_must_match_its_native_listener(self) -> None:
        import stat

        from sites.bodies.site_fpm import sfp_socket_metadata

        metadata: dict[str, object] = {"uid": 0, "gid": 99, "type": stat.S_IFSOCK, "mode": 0o600}
        self.assertFalse(sfp_socket_metadata("/run/example/diagnostic/listen.sock", metadata, 1201))
        self.assertFalse(sfp_socket_metadata("/run/example/status/listen.sock", metadata, 1201))
