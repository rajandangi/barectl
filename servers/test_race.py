"""Removal and discovery requests racing in two processes on one SQLite database.

The in-memory test database cannot hold two connections' transactions open at once, so
each request here runs in its own process against a temporary database file, with the
application's database settings. The first process holds its transaction open inside the
service call while the second one starts; files in a shared directory order the steps.

Run as ``python -m servers.test_race <action> <hold|follow> <directory>`` by the tests.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import ClassVar, override
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase

# How long the first process keeps its transaction open after the second one starts.
HOLD = 1.0
TIMEOUT = 20.0


class Signals:
    """Steps shared between the two processes as files in one directory."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def send(self, name: str) -> None:
        (self.directory / name).touch()

    def wait(self, name: str) -> None:
        deadline = time.monotonic() + TIMEOUT
        while not (self.directory / name).exists():
            if time.monotonic() > deadline:
                raise TimeoutError(name)
            time.sleep(0.01)


def _seed() -> dict[str, object]:
    from discovery.models import DiscoveryAttempt
    from discovery.test_attempts import record_attempt
    from servers.models import Server

    server = Server.objects.create(name="Web", ssh_alias="web.example.com")
    # Earlier history, which a refused removal must keep.
    record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    return {}


def _state() -> dict[str, object]:
    from django_tasks_db.models import DBTaskResult

    from discovery.models import DiscoveryAttempt
    from servers.models import Server

    return {
        "servers": Server.objects.count(),
        "attempts": sorted(DiscoveryAttempt.objects.values_list("status", flat=True)),
        "waiting_tasks": DBTaskResult.objects.filter(status="READY").count(),
    }


def _perform(action: str) -> str:
    from discovery.services import request_discovery
    from servers.models import Server
    from servers.registration import RemovalBlocked, remove_server

    # Loaded before the request's transaction, as a view loads it.
    server = Server.objects.get(name="Web")
    if action == "remove":
        try:
            remove_server(server)
        except RemovalBlocked:
            return "blocked"
        return "removed"
    try:
        request_discovery(server)
    except Server.DoesNotExist:
        return "gone"
    return "queued"


def _hold_inside(action: str, hold: Callable[[], None]) -> AbstractContextManager[object]:
    """Patch the service so it calls ``hold`` inside its transaction.

    Removal holds after reading which attempts to delete, before its first write. A
    deferred transaction holds only a read lock there, so the other request could take
    the write lock and each would wait for the other. Discovery holds after inserting
    its attempt.
    """
    from django.db.models.deletion import Collector

    from discovery.models import DiscoveryAttempt

    if action == "remove":
        delete = Collector.delete
        held: list[bool] = []

        def delete_after_hold(collector: Collector) -> tuple[int, dict[str, int]]:
            if not held:
                held.append(True)
                hold()
            return delete(collector)

        return mock.patch.object(Collector, "delete", delete_after_hold)
    create = DiscoveryAttempt.objects.create

    def create_then_hold(**fields: object) -> DiscoveryAttempt:
        attempt = create(**fields)
        hold()
        return attempt

    return mock.patch.object(DiscoveryAttempt.objects, "create", create_then_hold)


def _race(action: str, role: str, signals: Signals) -> dict[str, object]:
    other = "discover" if action == "remove" else "remove"
    if role == "hold":

        def hold() -> None:
            signals.send(f"{action}-holding")
            signals.wait(f"{other}-started")
            time.sleep(HOLD)

        with _hold_inside(action, hold):
            return {"outcome": _perform(action)}
    signals.wait(f"{other}-holding")
    signals.send(f"{action}-started")
    start = time.monotonic()
    outcome = _perform(action)
    return {"outcome": outcome, "waited": time.monotonic() - start}


def main(arguments: list[str]) -> None:
    import django

    django.setup()
    action = arguments[0]
    if action == "seed":
        result = _seed()
    elif action == "state":
        result = _state()
    else:
        result = _race(action, arguments[1], Signals(Path(arguments[2])))
    print(json.dumps(result))  # noqa: T201 - the parent test reads this line


def _run(environment: dict[str, str], *arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, *arguments],
        cwd=settings.BASE_DIR,
        env=environment,
        capture_output=True,
        text=True,
        timeout=TIMEOUT * 2,
        check=True,
    )
    return completed.stdout


class ConcurrentRemovalTests(SimpleTestCase):
    """A removal and a discovery request in separate processes, each order in turn."""

    template: ClassVar[Path]
    base_environment: ClassVar[dict[str, str]]
    directory: Path
    environment: dict[str, str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        shared = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        # The application's settings with the database file each test names.
        (shared / "race_settings.py").write_text(
            "import os\n"
            "from config.settings import *  # noqa: F403\n"
            "DATABASES = {'default': {**DATABASES['default'],  # noqa: F405\n"
            "    'NAME': os.environ['BARECTL_RACE_DATABASE']}}\n",
            encoding="utf-8",
        )
        cls.base_environment = os.environ | {
            "DJANGO_SETTINGS_MODULE": "race_settings",
            "PYTHONPATH": os.pathsep.join((str(shared), str(settings.BASE_DIR))),
            "BARECTL_DEBUG": "1",
            "BARECTL_SECRET_KEY": "local-development-race-test",
        }
        # Migrate and seed once; each test starts from a copy.
        cls.template = shared / "template.sqlite3"
        environment = cls.base_environment | {"BARECTL_RACE_DATABASE": str(cls.template)}
        _run(environment, "manage.py", "migrate", "--verbosity", "0")
        _run(environment, "-m", "servers.test_race", "seed")

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        database = self.directory / "db.sqlite3"
        shutil.copyfile(self.template, database)
        self.environment = self.base_environment | {"BARECTL_RACE_DATABASE": str(database)}

    def child(self, *arguments: str) -> dict[str, object]:
        output = _run(self.environment, "-m", "servers.test_race", *arguments)
        result: dict[str, object] = json.loads(output.splitlines()[-1])
        return result

    def race(self, first: str, second: str) -> tuple[dict[str, object], dict[str, object]]:
        """Run ``first`` holding its transaction open while ``second`` starts."""
        signals = str(self.directory)
        processes = [
            subprocess.Popen(  # noqa: S603 - fixed arguments
                [sys.executable, "-m", "servers.test_race", action, role, signals],
                cwd=settings.BASE_DIR,
                env=self.environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for action, role in ((first, "hold"), (second, "follow"))
        ]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=TIMEOUT * 2)
            self.assertEqual(process.returncode, 0, stderr)
            results.append(json.loads(stdout.splitlines()[-1]))
        return results[0], results[1]

    def assert_waited(self, result: dict[str, object]) -> None:
        # The second request waited for the first one's transaction, rather than failing.
        waited = result["waited"]
        self.assertIsInstance(waited, float)
        self.assertGreaterEqual(float(str(waited)), HOLD * 0.8)

    def test_discovery_requested_during_removal_finds_the_server_gone(self) -> None:
        removal, discovery = self.race("remove", "discover")
        self.assertEqual(removal["outcome"], "removed")
        self.assertEqual(discovery["outcome"], "gone")
        self.assert_waited(discovery)
        self.assertEqual(self.child("state"), {"servers": 0, "attempts": [], "waiting_tasks": 0})

    def test_removal_requested_during_discovery_is_refused(self) -> None:
        discovery, removal = self.race("discover", "remove")
        self.assertEqual(discovery["outcome"], "queued")
        self.assertEqual(removal["outcome"], "blocked")
        self.assert_waited(removal)
        # The refused removal kept the earlier history, and the check still waits.
        self.assertEqual(
            self.child("state"),
            {"servers": 1, "attempts": ["queued", "succeeded"], "waiting_tasks": 1},
        )


if __name__ == "__main__":
    main(sys.argv[1:])
