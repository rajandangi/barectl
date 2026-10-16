import os
import tempfile
import time
from pathlib import Path

from django.test import SimpleTestCase

from .bounded import TIMED_OUT, bounded


class BoundedProbeTests(SimpleTestCase):
    def test_output_and_pipeline_status_are_returned_exactly(self) -> None:
        self.assertEqual(bounded("printf 'a\\n b'"), (0, b"a\n b"))
        self.assertEqual(bounded("false | cat")[0], 1)

    def test_the_bound_stops_every_process_the_probe_started(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pids = Path(directory) / "pids"
            # A background child keeps the output open and one process ignores SIGTERM.
            command = (
                f"sleep 30 & echo $! >>{pids}; "
                f"sh -c 'trap \"\" TERM; echo $$ >>{pids}; sleep 30' & "
                "printf partial; wait"
            )
            started = time.monotonic()
            self.assertEqual(bounded(command, seconds=0.5), (TIMED_OUT, b""))
            self.assertLess(time.monotonic() - started, 3)
            # Killed orphans are reaped by init shortly after the signal.
            deadline = time.monotonic() + 2
            while (remaining := _running(pids.read_text().split())) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(remaining, [])


def _running(pids: list[str]) -> list[str]:
    running = []
    for pid in pids:
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            continue
        running.append(pid)
    return running
