"""A disposable server container the native harness boots and drives.

docs/quality.md#native-layer. A lane's server joins only its ``--internal`` network, so it
has no egress; the harness reaches it through the lane's forwarder.
"""

import contextlib
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass

from .docker import DockerError, docker, quietly

NAME_PREFIX = "barectl-native"


@dataclass
class Machine:
    name: str

    @classmethod
    def boot(
        cls,
        image: str,
        *,
        network: str | None = None,
        publish: Sequence[str] = (),
        extra: Sequence[str] = (),
        name: str | None = None,
        privileged: bool = True,
    ) -> Machine:
        chosen = name or f"{NAME_PREFIX}-{secrets.token_hex(4)}"
        arguments = ["run", "-d", "--name", chosen]
        if privileged:
            arguments.append("--privileged")
        if network:
            arguments += ["--network", network]
        for mapping in publish:
            arguments += ["-p", mapping]
        arguments += list(extra)
        arguments.append(image)
        docker(*arguments)
        machine = cls(chosen)
        try:
            machine.wait_for_systemd()
        except Exception:
            machine.remove()
            raise
        return machine

    def wait_for_systemd(self) -> None:
        state = ""
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            with contextlib.suppress(DockerError):
                state = self.exec("systemctl is-system-running || true").strip()
            if state in {"running", "degraded"}:
                return
            time.sleep(0.2)
        raise DockerError(f"systemd did not start in {self.name} (state: {state or 'unknown'})")

    def exec(self, script: str, *, timeout: float = 300, stdin: str | None = None) -> str:
        return docker("exec", "-i", self.name, "sh", "-c", script, timeout=timeout, stdin=stdin)

    def address(self, network: str) -> str:
        pattern = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
        return docker("inspect", "-f", pattern, self.name).strip()

    def boot_id(self) -> str:
        return self.exec("cat /proc/sys/kernel/random/boot_id").strip()

    def reboot(self, *, timeout: float = 120) -> None:
        """Restart the container's init and wait for systemd again.

        This is a userspace reboot of the same kernel, not a kernel reboot: the container
        shares the Docker VM's kernel. It re-runs every boot-time path Barectl relies on
        (unit enablement, timers, slice parenting) and is the closest the lane can prove
        without a virtual machine (docs/phase-c-qualification.md#not-qualified).
        """
        docker("restart", "--time", "10", self.name, timeout=timeout)
        self.wait_for_systemd()

    def remove(self) -> None:
        quietly("rm", "-f", self.name)
