import json
import stat
from typing import ClassVar
from unittest import TestCase

from sites.bodies.site_fpm import RetainedEntry, sfp_status_idle


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
        return {
            "pid": pid,
            "parent": parent,
            "title": title,
            "uid": [uid] * 4,
            "gid": [uid] * 4,
            "groups": [uid],
        }

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


class SiteFpmSampleStabilityTests(TestCase):
    """A shared ancestor's directory times are not part of the authenticated identity."""

    def directory(self) -> dict[str, object]:
        return {
            "uid": 0,
            "gid": 0,
            "mode": 0o755,
            "type": stat.S_IFDIR,
            "device": 1,
            "inode": 7,
            "links": 17,
            "ctime": 1_000,
            "mtime": 1_000,
        }

    def test_directory_times_and_link_count_may_change(self) -> None:
        from sites.bodies.site_fpm import sfp_same_metadata

        before = self.directory()
        after = before | {"ctime": 2_000, "mtime": 2_000, "links": 18}
        self.assertTrue(sfp_same_metadata(before, after))

    def test_directory_owner_mode_type_or_inode_may_not_change(self) -> None:
        from sites.bodies.site_fpm import sfp_same_metadata

        before = self.directory()
        for key, value in (
            ("uid", 1000),
            ("gid", 1000),
            ("mode", 0o775),
            ("type", stat.S_IFREG),
            ("device", 2),
            ("inode", 8),
        ):
            with self.subTest(key=key):
                self.assertFalse(sfp_same_metadata(before, before | {key: value}))

    def test_every_file_field_is_part_of_the_identity(self) -> None:
        from sites.bodies.site_fpm import sfp_same_metadata, sfp_same_trees

        before: dict[str, object] = {
            "uid": 0,
            "gid": 0,
            "mode": 0o644,
            "type": stat.S_IFREG,
            "device": 1,
            "inode": 9,
            "links": 1,
            "ctime": 1_000,
            "mtime": 1_000,
            "bytes": "YQ==",
        }
        for key, value in (
            ("mtime", 2_000),
            ("uid", 1000),
            ("mode", 0o600),
            ("bytes", "Yg=="),
            ("links", 2),
        ):
            with self.subTest(key=key):
                self.assertFalse(sfp_same_metadata(before, before | {key: value}))
        self.assertTrue(sfp_same_trees({"/a": before}, {"/a": dict(before)}))
        self.assertFalse(sfp_same_trees({"/a": before}, {}))
        self.assertFalse(sfp_same_trees({"/a": before}, {"/b": dict(before)}))


class SiteFpmRetainedShapeTests(TestCase):
    """The canonical-subtree admission for interrupted staging and cleanup (ADR 0038)."""

    expected: ClassVar[dict[str, str]] = {
        "/etc/php-fpm/sites/alpha/php85/php.ini": "opcache.enable=1\n",
        "/etc/php-fpm/sites/alpha/php85/php-fpm.conf": "[global]\n",
        "/etc/php-fpm/sites/alpha/php85/pools/alpha.conf": "[alpha]\n",
        "/etc/php-fpm/sites/alpha/php85/pools/diagnostic.conf": "[diagnostic]\n",
    }

    def entry(
        self, path: str, *, uid: int = 0, mode: int = 0o644, kind: str = "file", text: str = ""
    ) -> tuple[str, RetainedEntry]:
        return path, (uid, mode, kind, text.encode())

    def complete(self) -> dict[str, RetainedEntry]:
        base = "/etc/php-fpm/sites/alpha/php85"
        return {
            base: (0, 0o755, "dir", b""),
            base + "/pools": (0, 0o755, "dir", b""),
            **{path: (0, 0o644, "file", text.encode()) for path, text in self.expected.items()},
        }

    def test_full_canonical_tree_is_complete_and_recoverable_while_active(self) -> None:
        from sites.bodies.site_fpm import sfp_retained_shape

        observed = self.complete()
        self.assertEqual(sfp_retained_shape(self.expected, observed, True), "complete")
        self.assertEqual(sfp_retained_shape(self.expected, observed, False), "complete")

    def test_every_proper_subset_is_partial_only_while_the_service_is_inactive(self) -> None:
        from sites.bodies.site_fpm import sfp_retained_shape

        full = self.complete()
        for absent in self.expected:
            with self.subTest(absent=absent):
                observed = {path: value for path, value in full.items() if path != absent}
                self.assertEqual(sfp_retained_shape(self.expected, observed, False), "partial")
                self.assertEqual(sfp_retained_shape(self.expected, observed, True), "unsupported")

    def test_directory_only_survivor_is_partial(self) -> None:
        from sites.bodies.site_fpm import sfp_retained_shape

        base = "/etc/php-fpm/sites/alpha/php85"
        observed = dict([self.entry(base, mode=0o755, kind="dir")])
        self.assertEqual(sfp_retained_shape(self.expected, observed, False), "partial")

    def test_unknown_entry_symlink_owner_mode_or_content_refuses(self) -> None:
        from sites.bodies.site_fpm import sfp_retained_shape

        base = "/etc/php-fpm/sites/alpha/php85"
        path = base + "/php.ini"
        for name, entry in (
            ("unknown", self.entry(base + "/foreign.conf")),
            ("symlink", self.entry(path, kind="other")),
            ("owner", self.entry(path, uid=1000)),
            ("mode", self.entry(path, mode=0o644 | 0o020)),
            ("directory-mode", self.entry(base, mode=0o775, kind="dir")),
            ("content", self.entry(path, text="opcache.enable=0\n")),
            ("file-as-directory", self.entry(base, text="not a directory")),
        ):
            with self.subTest(name=name):
                observed = self.complete()
                observed.pop(path, None)
                observed[entry[0]] = entry[1]
                self.assertEqual(sfp_retained_shape(self.expected, observed, False), "unsupported")
