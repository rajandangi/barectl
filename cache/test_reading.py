"""The on-demand cache reading: bounds, permissions, storage and freshness (#392)."""

import contextlib
from datetime import timedelta
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
from django.test import SimpleTestCase
from django.utils import timezone

from discovery.ssh import CommandResult
from operations.lifecycle import OperationRefused
from operations.models import RemoteOperation
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from . import reading
from .convention import instance_paths
from .models import CacheReading

INFO = """\
# Server
valkey_version:9.0.4
connected_clients:1
used_memory:1048576
maxmemory:67108864
evicted_keys:3
"""


class InfoParsingTests(SimpleTestCase):
    def test_the_four_numbers_are_read(self) -> None:
        self.assertEqual(
            reading.parse_info(INFO),
            {
                "used_memory": 1048576,
                "maxmemory": 67108864,
                "evicted_keys": 3,
                "connected_clients": 1,
            },
        )

    def test_an_incomplete_or_non_numeric_answer_is_refused(self) -> None:
        for text in (
            "",
            "used_memory:1\nmaxmemory:2\nevicted_keys:3\n",
            INFO.replace("1048576", "1.5"),
            INFO.replace("used_memory:1048576\n", ""),
        ):
            with self.subTest(text=text[:20]):
                self.assertIsNone(reading.parse_info(text))

    def test_the_fixed_read_is_the_site_s_own_connection(self) -> None:
        command = reading.read_command("shop")
        paths = instance_paths("shop")
        self.assertIn("/usr/sbin/runuser -u sshop", command)
        self.assertIn(paths.socket, command)
        self.assertIn(" INFO", command)
        for identifier in ("Shop", "shop;reboot", "../shop"):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                reading.read_command(identifier)


class ReadingServiceTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation")
        self.server = Server.objects.create(name="Cache", ssh_alias="cache.example.com")

    def reading_row(self, *, state: str = "running", age: timedelta = timedelta()) -> CacheReading:
        return CacheReading.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            identifier="shop",
            requested_by=self.user,
            reading={"state": state, "used_memory": 1, "maxmemory": 2},
            reading_at=timezone.now() - age,
            status=RemoteOperation.Status.SUCCEEDED,
        )

    def test_a_reading_is_queued_for_a_site_reader(self) -> None:
        queued = reading.request_reading(self.server, self.user, "shop")
        if queued is None:
            self.fail("No reading was queued.")
        self.assertEqual(queued.identifier, "shop")
        self.assertEqual(queued.kind, RemoteOperation.Kind.CACHE_READING)
        self.assertEqual(queued.status, RemoteOperation.Status.QUEUED)

    def test_an_account_without_the_read_permission_is_refused(self) -> None:
        self.user.user_permissions.remove(Permission.objects.get(codename="view_siteobservation"))
        with self.assertRaises(OperationRefused):
            reading.request_reading(self.server, self.user, "shop")
        self.assertEqual(CacheReading.objects.count(), 0)

    def test_a_previous_reading_is_replaced_not_accumulated(self) -> None:
        self.reading_row()
        self.reading_row()
        reading.request_reading(self.server, self.user, "shop")
        self.assertEqual(CacheReading.objects.count(), 1)

    def test_a_reading_expires_after_a_day(self) -> None:
        self.reading_row(age=timedelta(hours=25))
        self.assertIsNone(reading.latest_reading(self.server, "shop"))

    def test_an_unknown_state_is_not_displayed(self) -> None:
        self.reading_row(state="mystery")
        self.assertIsNone(reading.latest_reading(self.server, "shop"))


class ReadingStepTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation")
        self.server = Server.objects.create(name="Cache", ssh_alias="cache.example.com")

    def run_step(self, result: CommandResult) -> CacheReading:
        row = CacheReading.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            identifier="shop",
            requested_by=self.user,
            status=RemoteOperation.Status.RUNNING,
        )
        with (
            mock.patch("cache.reading.connect_operation", return_value=contextlib.nullcontext()),
            mock.patch("cache.reading.run_root", return_value=result),
        ):
            reading._read(row)
        row.refresh_from_db()
        return row

    def test_a_running_instance_stores_its_numbers_on_the_request(self) -> None:
        row = self.run_step(CommandResult(0, INFO))
        self.assertEqual(row.status, RemoteOperation.Status.SUCCEEDED)
        self.assertEqual(row.reading["state"], "running")
        self.assertEqual(row.reading["evicted_keys"], 3)
        self.assertIsNotNone(row.reading_at)

    def test_a_stopped_or_unreadable_instance_is_recorded_honestly(self) -> None:
        stopped = self.run_step(CommandResult(1, "Could not connect to Valkey"))
        self.assertEqual(stopped.reading["state"], "stopped")
        unreadable = self.run_step(CommandResult(0, "not an info answer"))
        self.assertEqual(unreadable.reading["state"], "unreadable")
        truncated = self.run_step(CommandResult(0, INFO, truncated=True))
        self.assertEqual(truncated.reading["state"], "unreadable")
