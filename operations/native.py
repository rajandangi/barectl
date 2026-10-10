"""The native adapter every change runs through: transient unit submission, the shared
mutation lock, admission, inspection and the closure probe.

docs/adr/0006-use-native-bootstrap-execution.md
"""

import base64
import gzip
import hashlib
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
RUNTIME_MAX: Final = "30min"
TIMEOUT_STOP: Final = "60"
MAX_PAYLOAD: Final = 16 * 1024
# docs/adr/0006-use-native-bootstrap-execution.md#staged-bodies
MAX_BODY: Final = 192 * 1024
MAX_JOURNAL_OUTPUT: Final = 16 * 1024
RETAINED_LIMIT: Final = 100
# docs/ssh-connections.md#clearing-finished-bootstrap-runs
CLEANUP_CEILING: Final = RETAINED_LIMIT + 10
CLEANUP_BATCH: Final = CLEANUP_CEILING + 10


class Exit(IntEnum):
    """docs/adr/0006-use-native-bootstrap-execution.md#payload"""

    SUCCESS = 0
    LOCK_CONFLICT = 10
    UNSAFE_LOCK = 11
    BOOT_CHANGED = 12
    EXPIRED = 13
    OTHER_RUN_ACTIVE = 14
    DRIFT = 15
    PACKAGE_MANAGER_BUSY = 16
    UPDATE_FAILED = 17
    CAPACITY = 18
    CLEANUP_FAILED = 19
    INSTALL_FAILED = 20
    TRANSACTION_REFUSED = 21
    SERVICE_FAILED = 22
    INSTALL_NOT_STARTED = 23
    VALIDATION_FAILED = 24
    RENEWAL_ACTIVE = 25
    RELOAD_FAILED = 26


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
    Exit.CAPACITY: Execution.CAPACITY,
    Exit.CLEANUP_FAILED: Execution.FAILED,
    Exit.INSTALL_FAILED: Execution.INSTALL_FAILED,
    Exit.TRANSACTION_REFUSED: Execution.TRANSACTION_REFUSED,
    Exit.SERVICE_FAILED: Execution.SERVICE_FAILED,
    Exit.INSTALL_NOT_STARTED: Execution.INSTALL_NOT_STARTED,
    Exit.VALIDATION_FAILED: Execution.VALIDATION_FAILED,
    Exit.RENEWAL_ACTIVE: Execution.RENEWAL_ACTIVE,
    Exit.RELOAD_FAILED: Execution.RELOAD_FAILED,
}

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
CLD_EXITED = 1
_CLD_SIGNALLED = frozenset({2, 3})


class PayloadTooLarge(Exception):
    pass


class Unreadable(Exception):
    """Native evidence that is not in the form systemd and the kernel report."""


def new_unit_name() -> str:
    return f"{UNIT_PREFIX}{uuid.uuid4().hex}.service"


def parse_digest(text: str) -> str:
    digest = text.split(" ", 1)[0].strip()
    if not _DIGEST.fullmatch(digest):
        raise Unreadable("sha256sum did not report a digest.")
    return digest


def checked(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"Not a valid {what}.")
    return value


def lock_steps(unsafe: str, conflict: str) -> list[str]:
    """docs/adr/0006-use-native-bootstrap-execution.md#payload: take the mutation lock on
    descriptor 9 without waiting, running ``unsafe`` or ``conflict`` when it cannot.

    Certbot's guarded renewal takes the lock with these same steps (docs/tls.md).
    """
    return [
        "export LC_ALL=C",
        f"d={LOCK_DIRECTORY}",
        f"f={LOCK_FILE}",
        'mkdir -m 0700 "$d" 2>/dev/null',
        f"[ \"$(stat -c '%F %u %a' \"$d\")\" = 'directory 0 700' ] || {unsafe}",
        f'[ ! -L "$f" ] || {unsafe}',
        f'exec 9>>"$f" || {unsafe}',
        f"[ \"$(stat -c '%F %u %h' \"$f\")\" = 'regular empty file 0 1' ] || {unsafe}",
        f"flock -n 9 || {conflict}",
    ]


def _lock() -> list[str]:
    return lock_steps(f"exit {Exit.UNSAFE_LOCK}", f"exit {Exit.LOCK_CONFLICT}")


# Every bootstrap unit's control-group events file; a unit's is present while it runs.
_UNIT_EVENTS = f"/sys/fs/cgroup/system.slice/{UNIT_PREFIX}*.service/cgroup.events"
# docs/adr/0006-use-native-bootstrap-execution.md#payload: Certbot's packaged renewal
# service, at its fixed path and wherever systemd reports its control group.
_RENEWAL = (
    "r=0; c=$(systemctl show -p ControlGroup --value certbot.service 2>/dev/null); "
    "for e in /sys/fs/cgroup/system.slice/certbot.service/cgroup.events "
    '${c:+"/sys/fs/cgroup$c/cgroup.events"}; do '
    "grep -qx 'populated 1' \"$e\" 2>/dev/null && r=1; done"
)


def renewal_check() -> list[str]:
    """Exit RENEWAL_ACTIVE while Certbot's renewal service has processes."""
    return [_RENEWAL, f'[ "$r" = 0 ] || exit {Exit.RENEWAL_ACTIVE}']


_RETAINED_COUNT = (
    f"systemctl list-units --all --plain --no-legend --type=service '{UNIT_PREFIX}*' | grep -c ."
)


def admission(
    unit: str, boot_id: str, deadline_centiseconds: int, *, capacity: int = RETAINED_LIMIT
) -> list[str]:
    unit = checked(_UNIT, unit, "unit name")
    boot_id = checked(_BOOT, boot_id, "boot ID")
    deadline = int(deadline_centiseconds)
    limit = int(capacity)
    own = f"/sys/fs/cgroup/system.slice/{unit}/cgroup.events"
    return [
        *_lock(),
        f'[ "$(cat /proc/sys/kernel/random/boot_id)" = {boot_id} ] || exit {Exit.BOOT_CHANGED}',
        f"[ \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\" -lt {deadline} ] || exit {Exit.EXPIRED}",
        (
            f"for e in {_UNIT_EVENTS}; do "
            f'[ "$e" = {own} ] && continue; [ -e "$e" ] || continue; '
            f"grep -qx 'populated 1' \"$e\" && exit {Exit.OTHER_RUN_ACTIVE}; done"
        ),
        *renewal_check(),
        # The run's own unit is listed too.
        f"n=$({_RETAINED_COUNT})",
        f'[ "$((n - 1))" -lt {limit} ] || exit {Exit.CAPACITY}',
    ]


def archive_cache(unit: str) -> str:
    checked(_UNIT, unit, "unit name")
    return f"/run/barectl-apt-{unit.removeprefix(UNIT_PREFIX).removesuffix('.service')}/archives/"


def digest_preconditions(checks: tuple[tuple[str, str], ...]) -> list[str]:
    steps: list[str] = []
    for script, digest in checks:
        checked(_DIGEST, digest, "digest")
        if len(script.encode()) > 4000 or not script.endswith("| sha256sum"):
            raise ValueError("Not a fixed digest precondition.")
        steps.append(f'[ "$( {script} | cut -d" " -f1)" = {digest} ] || exit {Exit.DRIFT}')
    return steps


class Probe(IntEnum):
    LOCKED = 0
    LOCK_CONFLICT = Exit.LOCK_CONFLICT
    UNSAFE_LOCK = Exit.UNSAFE_LOCK


def closure_probe(unit: str) -> list[str]:
    """docs/adr/0006-use-native-bootstrap-execution.md#unknown-outcomes"""
    unit = checked(_UNIT, unit, "unit name")
    steps = [
        *_lock(),
        "cat /proc/sys/kernel/random/boot_id",
        "cut -d' ' -f1 /proc/uptime | tr -d .",
        (
            f'p=0; for e in {_UNIT_EVENTS}; do [ -e "$e" ] || continue; '
            'grep -qx \'populated 1\' "$e" && p=$((p + 1)); done; echo "populated $p"'
        ),
        f"systemctl show --value -p LoadState {unit}",
        _RENEWAL,
        'echo "renewal $r"',
        f"exit {Probe.LOCKED}",
    ]
    return ["/usr/bin/sh", "-c", "; ".join(steps)]


@dataclass(frozen=True)
class ProbeEvidence:
    boot_id: str
    uptime_centiseconds: int
    # Bootstrap units whose control groups still have processes.
    populated: int
    unit_loaded: bool
    # Certbot's renewal service still has processes.
    renewal_active: bool


def parse_probe(text: str) -> ProbeEvidence:
    lines = text.splitlines()
    if (
        len(lines) != 5
        or not _BOOT.fullmatch(lines[0])
        or not re.fullmatch(r"\d{1,15}", lines[1])
        or not (populated := re.fullmatch(r"populated (\d{1,4})", lines[2]))
        or not re.fullmatch(r"[a-z-]{1,30}", lines[3])
        or not (renewal := re.fullmatch(r"renewal ([01])", lines[4]))
    ):
        raise Unreadable("The closure probe is not in its expected form.")
    return ProbeEvidence(
        lines[0], int(lines[1]), int(populated[1]), lines[3] != "not-found", renewal[1] == "1"
    )


@dataclass(frozen=True)
class Limits:
    """Native limits a reviewed action sets on its transient unit's processes, which every
    child inherits (docs/adr/0006-use-native-bootstrap-execution.md#submission)."""

    file_bytes: int
    memory_bytes: int

    def properties(self) -> list[str]:
        if not (0 < self.file_bytes < 2**40 and 0 < self.memory_bytes < 2**40):
            raise ValueError("Not valid unit limits.")
        return [
            f"--property=LimitFSIZE={int(self.file_bytes)}",
            f"--property=MemoryMax={int(self.memory_bytes)}",
            "--property=MemorySwapMax=0",
        ]


def staged(body: str) -> list[str]:
    """docs/adr/0006-use-native-bootstrap-execution.md#staged-bodies: the steps that decode a
    compressed reviewed ``body``, refuse it unless its SHA-256 is the reviewed one, and run
    it in the payload's own shell, which holds the mutation lock.

    The body must not end with a newline: command substitution would strip it.
    """
    raw = body.encode()
    if not raw or len(raw) > MAX_BODY or b"\0" in raw or body.endswith("\n"):
        raise ValueError("Not a valid staged body.")
    packed = base64.b64encode(gzip.compress(raw, 9, mtime=0)).decode()
    digest = hashlib.sha256(raw).hexdigest()
    return [
        (
            f"b=$(printf %s '{packed}' | base64 -d 2>/dev/null | gzip -dc 2>/dev/null "
            f"| head -c {MAX_BODY + 1})"
        ),
        f'[ "$(printf %s "$b" | sha256sum | cut -d\' \' -f1)" = {digest} ] || exit {Exit.DRIFT}',
        'eval "$b"',
    ]


def submission(
    unit: str,
    script: str,
    *,
    isolated_archives: bool = False,
    limits: Limits | None = None,
) -> list[str]:
    """docs/adr/0006-use-native-bootstrap-execution.md#submission"""
    checked(_UNIT, unit, "unit name")
    if len(script.encode()) > MAX_PAYLOAD:
        raise PayloadTooLarge
    runtime = []
    if isolated_archives:
        directory = archive_cache(unit).split("/")[2]
        runtime = [
            f"--property=RuntimeDirectory={directory}",
            "--property=RuntimeDirectoryMode=0755",
            "--property=RuntimeDirectoryPreserve=no",
        ]
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
        *runtime,
        *(limits.properties() if limits is not None else []),
        "/usr/bin/sh",
        "-c",
        script,
    ]


def privileged(argv: list[str], *, root: bool) -> str:
    command = shlex.join(argv)
    return command if root else f"sudo -n {command}"


def authorization(argv: list[str]) -> str:
    """Lists whether sudo authorizes exactly ``argv`` without a password; runs nothing."""
    return f"sudo -n -l {shlex.join(argv)}"


def is_root(shell: RemoteShell) -> bool | None:
    result = shell.run(USER_ID)
    if result.exit_status != 0 or result.truncated:
        return None
    return result.stdout.strip() == "0"


def retained_units(shell: RemoteShell) -> int | None:
    result = shell.run(RETAINED_UNITS)
    if result.exit_status != 0 or result.truncated:
        return None
    return sum(1 for line in result.stdout.splitlines() if UNIT_PREFIX in line)


def inspection(unit: str) -> str:
    checked(_UNIT, unit, "unit name")
    return f"cat /proc/sys/kernel/random/boot_id; {_unit_report(unit)}"


@dataclass(frozen=True)
class UnitEvidence:
    unit: str
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
        if not self.found or self.populated:
            return False
        exited = self.active_state == "active" and self.sub_state == "exited"
        return exited or self.active_state in {"failed", "inactive"}

    @property
    def execution(self) -> Execution:
        if not self.found:
            return Execution.NOT_FOUND
        if not self.terminal:
            return Execution.RUNNING
        if self.result == "timeout":
            return Execution.TIMED_OUT
        if self.exec_main_code in _CLD_SIGNALLED:
            return Execution.KILLED
        if self.exec_main_code != CLD_EXITED:
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
    lines = text.splitlines()
    if len(lines) != len(_PROPERTIES) + 2 or not _BOOT.fullmatch(lines[0]):
        raise Unreadable("The unit inspection is not in systemd's form.")
    return _parse_unit(lines[0], lines[1:], unit)


def _parse_unit(boot_id: str, lines: list[str], unit: str | None) -> UnitEvidence:
    """``unit`` is the expected name, or ``None`` for any bootstrap unit."""
    values: dict[str, str] = {}
    for line in lines[:-1]:
        key, separator, value = line.partition("=")
        if not separator or key not in _PROPERTIES or len(value) > 200:
            raise Unreadable("The unit inspection is not in systemd's form.")
        values[key] = value
    populated = re.fullmatch(r"populated ([01])", lines[-1])
    if set(values) != set(_PROPERTIES) or populated is None:
        raise Unreadable("The unit inspection is not in systemd's form.")
    expected = values["Id"] == unit if unit is not None else _UNIT.fullmatch(values["Id"])
    if not expected:
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
        unit=values["Id"],
        boot_id=boot_id,
        found=values["LoadState"] != "not-found",
        active_state=values["ActiveState"],
        sub_state=values["SubState"],
        result=values["Result"],
        exec_main_code=int(values["ExecMainCode"]),
        exec_main_status=int(values["ExecMainStatus"]),
        invocation_id=values["InvocationID"],
        populated=populated[1] == "1",
    )


def _unit_report(unit: str) -> str:
    """``unit`` is a validated name, or the quoted shell variable holding one."""
    properties = " ".join(f"-p {name}" for name in _PROPERTIES)
    events = '"/sys/fs/cgroup$cg/cgroup.events"'
    # docs/adr/0006-use-native-bootstrap-execution.md#inspection-and-outcomes
    return (
        f"systemctl show {properties} {unit}; "
        f"cg=$(systemctl show -p ControlGroup --value {unit}); "
        f'if [ -n "$cg" ] && [ -r {events} ]; then '
        f"grep '^populated ' {events} 2>/dev/null "
        f"|| {{ [ ! -e {events} ] && echo 'populated 0'; }}; "
        "else echo 'populated 0'; fi"
    )


RETAINED_STATES: Final = (
    "cat /proc/sys/kernel/random/boot_id; "
    f"for u in $({RETAINED_UNITS} | cut -d' ' -f1); do {_unit_report('"$u"')}; done"
)


def parse_retained_states(text: str) -> tuple[str, list[UnitEvidence]]:
    lines = text.splitlines()
    size = len(_PROPERTIES) + 1
    if not lines or not _BOOT.fullmatch(lines[0]) or (len(lines) - 1) % size:
        raise Unreadable("The retained units are not in systemd's form.")
    return lines[0], [
        _parse_unit(lines[0], lines[start : start + size], None)
        for start in range(1, len(lines), size)
    ]


def inspect(shell: RemoteShell, unit: str) -> UnitEvidence:
    result = shell.run(inspection(unit))
    if result.exit_status != 0 or result.truncated:
        raise Unreadable("The unit could not be inspected.")
    return parse_inspection(result.stdout, unit)
