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

    def remove(self) -> None:
        quietly("rm", "-f", self.name)
