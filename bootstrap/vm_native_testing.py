"""Real-kernel fixtures (docs/ssh-connections.md#acceptance-against-a-real-server)."""

import shlex
import subprocess
import time
from typing import override

from discovery.native_testing import setting

from .apply_remote_testing import ApplyAcceptanceTestCase


class VmAcceptanceTestCase(ApplyAcceptanceTestCase):
    @override
    def administer(self, script: str, *, detach: bool = False, timeout: float = 900) -> str:
        """Run ``script`` as root through OpenSSH, outside Barectl; return its output.

        A detached script runs as a transient unit of its own, which a reboot ends.
        """
        if detach:
            script = f"systemd-run --quiet --collect sh -c {shlex.quote(script)}"
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            [  # noqa: S607
                "ssh",
                "-q",
                "-i",
                setting("KEY"),
                "-p",
                setting("PORT"),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                f"UserKnownHostsFile={setting('KNOWN_HOSTS')}",
                "-o",
                "StrictHostKeyChecking=yes",
                f"{setting('USER')}@{setting('HOST')}",
                f"sudo sh -c {shlex.quote(script)}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout

    def boot(self, timeout: float = 60) -> tuple[str, int]:
        """The kernel's boot ID and its monotonic uptime in hundredths of a second."""
        boot, uptime = self.administer(
            "cat /proc/sys/kernel/random/boot_id; cut -d' ' -f1 /proc/uptime | tr -d .",
            timeout=timeout,
        ).split()
        return boot, int(uptime)

    def reboot_when(self, condition: str) -> tuple[str, int]:
        """Have the server reboot its kernel as soon as ``condition`` holds there.

        The server itself waits for the condition, so the reboot follows it at once.
        Returns the boot ID and uptime read before, for ``rebooted``.
        """
        before = self.boot()
        self.administer(
            f"until {condition}; do sleep 0.05; done; systemctl reboot --check-inhibitors=no",
            detach=True,
        )
        return before

    def rebooted(self, before: tuple[str, int], unit: str = "") -> None:
        """Wait until the server is back in a boot other than ``before``'s.

        When it never went away, the failure shows what ``unit`` logged, such as a run
        that stopped before dpkg unpacked anything.
        """
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            time.sleep(5)
            try:
                if self.boot(timeout=30)[0] != before[0]:
                    self.administer("systemctl is-system-running --wait >/dev/null; true")
                    return
            except subprocess.CalledProcessError, subprocess.TimeoutExpired:
                continue
        logged = self.journal(unit)[-3000:] if unit else ""
        raise AssertionError(f"The server did not come back after rebooting.\n{logged}")
