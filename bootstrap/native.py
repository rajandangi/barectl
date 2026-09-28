"""Native execution of reviewed actions: the payload, its submission and its inspection.

This is the one infrastructure adapter apply services use to reach a server's native
execution (ADR 0006). It builds fixed shell text and runs it through the ``RemoteShell``
that ``discovery.ssh`` opens, pyinfra's documented shell interface; discovery's contract
is unchanged. Nothing is uploaded and no helper is installed.

A run is one transient systemd system service, submitted with ``systemd-run`` under a
unique unit name that the application saved before sending anything. The service's
payload is a finite POSIX shell program built only from fixed text and validated
parameters. It takes Barectl's one nonblocking mutation lock, checks the reviewed boot and
the server-monotonic admission deadline, refuses while another bootstrap unit still has
processes, rechecks the reviewed APT evidence, and only then runs the authorized action.
Each refusal exits with its own status before any requested change. systemd, not the
controller or its SSH connection, owns the execution: the connection only submits and
later inspects the unit by name.

Inspection reads the unit's systemd properties and whether its control group still has
processes. Native success requires a normal exit with status zero, a successful result and
an empty control group; ``Result=success`` alone is not enough. The payload's output goes
to the native journal, bounded; Barectl never reads or stores it.
"""

import re
import shlex
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from discovery.ssh import RemoteShell

from .models import Execution

UNIT_PREFIX: Final = "barectl-apply-"
_UNIT = re.compile(r"barectl-apply-[0-9a-f]{32}\.service")
_BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
LOCK_DIRECTORY: Final = "/run/lock/barectl"
LOCK_FILE: Final = f"{LOCK_DIRECTORY}/mutation.lock"
SYSTEMD_RUN: Final = "/usr/bin/systemd-run"
# systemd.service(5) limits: the run may take 30 minutes, and stopping it 60 seconds more
# before systemd kills what remains of its control group.
RUNTIME_MAX: Final = "30min"
TIMEOUT_STOP: Final = "60"
# The largest payload Barectl submits. A larger one is refused, never split.
MAX_PAYLOAD: Final = 16 * 1024
# The most payload output kept in the native journal.
MAX_JOURNAL_OUTPUT: Final = 16 * 1024
# New submissions are refused while this many bootstrap units are retained.
RETAINED_LIMIT: Final = 100


class Exit(IntEnum):
    """The payload's exit statuses. Every one except SUCCESS and UPDATE_FAILED stops
    before anything the plan authorizes has run."""

    SUCCESS = 0
    LOCK_CONFLICT = 10
    UNSAFE_LOCK = 11
    BOOT_CHANGED = 12
    EXPIRED = 13
    OTHER_RUN_ACTIVE = 14
    DRIFT = 15
    PACKAGE_MANAGER_BUSY = 16
    UPDATE_FAILED = 17


_EXECUTIONS = {
    Exit.SUCCESS: Execution.SUCCEEDED,
    Exit.LOCK_CONFLICT: Execution.LOCK_CONFLICT,
    Exit.UNSAFE_LOCK: Execution.UNSAFE_LOCK,
    Exit.BOOT_CHANGED: Execution.BOOT_CHANGED,
    Exit.EXPIRED: Execution.EXPIRED,
    Exit.OTHER_RUN_ACTIVE: Execution.OTHER_RUN_ACTIVE,
    Exit.DRIFT: Execution.DRIFT,
    Exit.PACKAGE_MANAGER_BUSY: Execution.PACKAGE_MANAGER_BUSY,
    Exit.UPDATE_FAILED: Execution.FAILED,
}

# The APT evidence a plan records and the payload recomputes under the lock: the effective
# configuration with every hook, the digest of every file under /etc/apt except
# authentication files, and the configured sources, in a fixed order. The same text runs
# unprivileged during preparation and as root in the payload; on the acceptance server
# both give the same digest.
APT_DIGEST: Final = (
    "{ LC_ALL=C apt-config dump; "
    "find /etc/apt -xdev -type f ! -path '/etc/apt/auth.conf*' -exec sha256sum -- {} + "
    "| LC_ALL=C sort; "
    "LC_ALL=C apt-get indextargets --no-release-info --format "
    "'$(SITE)|$(RELEASE)|$(COMPONENT)' 'Created-By: Packages' | LC_ALL=C sort; "
    "} 2>/dev/null | sha256sum"
)
DPKG_STATUS_DIGEST: Final = "sha256sum /var/lib/dpkg/status"
USER_ID: Final = "id -u"
RETAINED_UNITS: Final = (
    f"systemctl list-units --all --plain --no-legend --type=service '{UNIT_PREFIX}*'"
)
_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "InvocationID",
)
# waitid(2) codes that systemd reports as ExecMainCode.
_CLD_EXITED = 1
_CLD_SIGNALLED = frozenset({2, 3})


class PayloadTooLarge(Exception):
    """The payload is larger than Barectl submits."""


class Unreadable(Exception):
    """Native evidence that is not in the form systemd and the kernel report."""


def new_unit_name() -> str:
    """A unique transient unit name for one apply run."""
    return f"{UNIT_PREFIX}{uuid.uuid4().hex}.service"


def parse_digest(text: str) -> str:
    """The hexadecimal digest ``sha256sum`` printed first."""
    digest = text.split(" ", 1)[0].strip()
    if not _DIGEST.fullmatch(digest):
        raise Unreadable("sha256sum did not report a digest.")
    return digest


def _check(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"Not a valid {what}.")
    return value


def admission(unit: str, boot_id: str, deadline_centiseconds: int) -> list[str]:
    """The payload's first steps, which every reviewed action shares.

    They create the private lock directory if needed, refuse an unsafe one, open the
    empty lock file without replacing it, take the lock without waiting, then check the
    boot, the deadline and that no other bootstrap unit still has processes. The lock
    stays held through descriptor 9, which children inherit.
    """
    unit = _check(_UNIT, unit, "unit name")
    boot_id = _check(_BOOT, boot_id, "boot ID")
    deadline = int(deadline_centiseconds)
    own = f"/sys/fs/cgroup/system.slice/{unit}/cgroup.events"
    return [
        "export LC_ALL=C",
        f"d={LOCK_DIRECTORY}",
        f"f={LOCK_FILE}",
        'mkdir -m 0700 "$d" 2>/dev/null',
        f"[ \"$(stat -c '%F %u %a' \"$d\")\" = 'directory 0 700' ] || exit {Exit.UNSAFE_LOCK}",
        f'[ ! -L "$f" ] || exit {Exit.UNSAFE_LOCK}',
        f'exec 9>>"$f" || exit {Exit.UNSAFE_LOCK}',
        (
            f"[ \"$(stat -c '%F %u %h' \"$f\")\" = 'regular empty file 0 1' ] "
            f"|| exit {Exit.UNSAFE_LOCK}"
        ),
        f"flock -n 9 || exit {Exit.LOCK_CONFLICT}",
        f'[ "$(cat /proc/sys/kernel/random/boot_id)" = {boot_id} ] || exit {Exit.BOOT_CHANGED}',
        f"[ \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\" -lt {deadline} ] || exit {Exit.EXPIRED}",
        (
            f"for e in /sys/fs/cgroup/system.slice/{UNIT_PREFIX}*.service/cgroup.events; do "
            f'[ "$e" = {own} ] && continue; [ -e "$e" ] || continue; '
            f"grep -qx 'populated 1' \"$e\" && exit {Exit.OTHER_RUN_ACTIVE}; done"
        ),
    ]


def metadata_refresh(unit: str, boot_id: str, deadline_centiseconds: int, apt: str) -> str:
    """The payload of a reviewed package metadata refresh.

    After admission it recomputes the APT digest, so any changed configuration, hook,
    source or preference refuses the run, then runs ``apt-get update`` in the foreground.
    ``--error-on=any`` makes any failed index fail the update, APT's lists lock refuses
    concurrent package-manager work without waiting, and any error or warning line fails
    the run, since a partial update would otherwise exit zero.
    """
    apt = _check(_DIGEST, apt, "digest")
    steps = [
        *admission(unit, boot_id, deadline_centiseconds),
        f'[ "$({APT_DIGEST} | cut -d" " -f1)" = {apt} ] || exit {Exit.DRIFT}',
        "o=$(apt-get -q --error-on=any update 2>&1); s=$?",
        f"printf '%s\\n' \"$o\" | tail -c {MAX_JOURNAL_OUTPUT}",
        f"case \"$o\" in *'Could not get lock'*) exit {Exit.PACKAGE_MANAGER_BUSY};; esac",
        f'[ "$s" -eq 0 ] || exit {Exit.UPDATE_FAILED}',
        f"printf '%s\\n' \"$o\" | grep -Eq '^(W:|E:|Err:)' && exit {Exit.UPDATE_FAILED}",
        f"exit {Exit.SUCCESS}",
    ]
    return "; ".join(steps)


def submission(unit: str, script: str) -> list[str]:
    """The ``systemd-run`` command line that starts ``script`` as the transient unit.

    systemd-run(1) and systemd.service(5) of systemd 255: a system service (no scope),
    started once its main process is executed, alive while its control group has
    processes, never restarted, stopped at the runtime limit, and with the whole control
    group terminated on stop. Input is null, output goes to the journal, and no PTY or
    pipe is attached, so the SSH connection owns nothing of it. The payload is passed
    literally, without systemd's environment variable expansion. The unit is kept after it
    exits, successful or failed, until explicitly cleared.
    """
    _check(_UNIT, unit, "unit name")
    if len(script.encode()) > MAX_PAYLOAD:
        raise PayloadTooLarge
    return [
        SYSTEMD_RUN,
        f"--unit={unit}",
        "--description=Barectl reviewed apply",
        "--quiet",
        "--expand-environment=no",
        "--service-type=exec",
        "--remain-after-exit",
        "--property=ExitType=cgroup",
        "--property=Restart=no",
        f"--property=RuntimeMaxSec={RUNTIME_MAX}",
        f"--property=TimeoutStopSec={TIMEOUT_STOP}",
        "--property=KillMode=control-group",
        "--property=StandardInput=null",
        "--property=StandardOutput=journal",
        "--property=StandardError=journal",
        "/usr/bin/sh",
        "-c",
        script,
    ]


def privileged(argv: list[str], *, root: bool) -> str:
    """``argv`` as a command run as root: directly for root, else through noninteractive sudo."""
    command = shlex.join(argv)
    return command if root else f"sudo -n {command}"


def authorization(argv: list[str]) -> str:
    """Lists whether sudo authorizes exactly ``argv`` without a password; runs nothing."""
    return f"sudo -n -l {shlex.join(argv)}"


def is_root(shell: RemoteShell) -> bool | None:
    """Whether the SSH user is root, or ``None`` when that could not be read."""
    result = shell.run(USER_ID)
    if result.exit_status != 0 or result.truncated:
        return None
    return result.stdout.strip() == "0"


def retained_units(shell: RemoteShell) -> int | None:
    """How many bootstrap units systemd keeps, or ``None`` when that could not be read."""
    result = shell.run(RETAINED_UNITS)
    if result.exit_status != 0 or result.truncated:
        return None
    return sum(1 for line in result.stdout.splitlines() if UNIT_PREFIX in line)


def inspection(unit: str) -> str:
    """Reads the boot, the unit's properties, and whether its control group has processes."""
    _check(_UNIT, unit, "unit name")
    properties = " ".join(f"-p {name}" for name in _PROPERTIES)
    return (
        "cat /proc/sys/kernel/random/boot_id; "
        f"systemctl show {properties} {unit}; "
        f"cg=$(systemctl show -p ControlGroup --value {unit}); "
        'if [ -n "$cg" ] && [ -r "/sys/fs/cgroup$cg/cgroup.events" ]; then '
        "grep '^populated ' \"/sys/fs/cgroup$cg/cgroup.events\"; else echo 'populated 0'; fi"
    )


@dataclass(frozen=True)
class UnitEvidence:
    """One inspection of a transient unit, as systemd and the kernel reported it."""

    boot_id: str
    found: bool
    active_state: str
    sub_state: str
    result: str
    exec_main_code: int
    exec_main_status: int
    invocation_id: str
    # The unit's control group still has processes.
    populated: bool

    @property
    def terminal(self) -> bool:
        """The unit ran and nothing of it remains running."""
        if not self.found or self.populated:
            return False
        exited = self.active_state == "active" and self.sub_state == "exited"
        return exited or self.active_state in {"failed", "inactive"}

    @property
    def execution(self) -> Execution:
        """The execution outcome this evidence establishes."""
        if not self.found:
            return Execution.NOT_FOUND
        if not self.terminal:
            return Execution.RUNNING
        if self.result == "timeout":
            return Execution.TIMED_OUT
        if self.exec_main_code in _CLD_SIGNALLED:
            return Execution.KILLED
        if self.exec_main_code != _CLD_EXITED:
            # The main process never ran, such as a unit that failed to start.
            return Execution.FAILED
        try:
            outcome = _EXECUTIONS[Exit(self.exec_main_status)]
        except ValueError:
            return Execution.FAILED
        if outcome == Execution.SUCCEEDED and self.result != "success":
            return Execution.FAILED
        return outcome


def parse_inspection(text: str, unit: str) -> UnitEvidence:
    """Read ``inspection``'s output strictly; anything else is ``Unreadable``."""
    lines = text.splitlines()
    if len(lines) != len(_PROPERTIES) + 2 or not _BOOT.fullmatch(lines[0]):
        raise Unreadable("The unit inspection is not in systemd's form.")
    values: dict[str, str] = {}
    for line in lines[1:-1]:
        key, separator, value = line.partition("=")
        if not separator or key not in _PROPERTIES or len(value) > 200:
            raise Unreadable("The unit inspection is not in systemd's form.")
        values[key] = value
    populated = re.fullmatch(r"populated ([01])", lines[-1])
    if set(values) != set(_PROPERTIES) or values["Id"] != unit or populated is None:
        raise Unreadable("The unit inspection is not in systemd's form.")
    token = re.compile(r"[a-z-]{1,30}")
    states = (values["LoadState"], values["ActiveState"], values["SubState"], values["Result"])
    codes = (values["ExecMainCode"], values["ExecMainStatus"])
    if not all(token.fullmatch(state) for state in states) or not all(
        re.fullmatch(r"\d{1,3}", code) for code in codes
    ):
        raise Unreadable("The unit inspection is not in systemd's form.")
    if not re.fullmatch(r"[0-9a-f]{32}|", values["InvocationID"]):
        raise Unreadable("The unit inspection is not in systemd's form.")
    return UnitEvidence(
        boot_id=lines[0],
        found=values["LoadState"] != "not-found",
        active_state=values["ActiveState"],
        sub_state=values["SubState"],
        result=values["Result"],
        exec_main_code=int(values["ExecMainCode"]),
        exec_main_status=int(values["ExecMainStatus"]),
        invocation_id=values["InvocationID"],
        populated=populated[1] == "1",
    )


def inspect(shell: RemoteShell, unit: str) -> UnitEvidence:
    """Inspect ``unit`` through ``shell``; raise ``Unreadable`` when that is not possible."""
    result = shell.run(inspection(unit))
    if result.exit_status != 0 or result.truncated:
        raise Unreadable("The unit could not be inspected.")
    return parse_inspection(result.stdout, unit)
