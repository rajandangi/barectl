"""docs/quality.md#limits: the host-wide native lock is one file every runner takes."""

import fcntl
import os
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from . import locking


class LockPathTests(TestCase):
    def test_the_lock_lives_in_the_temporary_directory_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(locking.lock_path(), Path(tempfile.gettempdir()) / locking.LOCK_NAME)

    def test_an_explicit_path_wins(self) -> None:
        with patch.dict(os.environ, {locking.LOCK_ENV: "/run/barectl/native.lock"}):
            self.assertEqual(locking.lock_path(), Path("/run/barectl/native.lock"))

    def test_the_waiting_message_names_the_lock_the_waiter_holds(self) -> None:
        self.assertEqual(locking.WAITING, "waiting for the native lock at ")


class HostLockTests(TestCase):
    def test_a_held_lock_excludes_a_second_holder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / locking.LOCK_NAME
            with (
                patch.dict(os.environ, {locking.LOCK_ENV: str(path)}),
                locking.host_lock(lambda message: None),
            ):
                other = path.open("w", encoding="utf-8")
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                other.close()
