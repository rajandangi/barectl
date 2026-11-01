"""docs/adr/0023-change-server-access-with-native-confirm-or-revert.md

The one confirm-or-revert window an access-changing kind uses. The kind's body saves a
root-only recovery preimage, arms a transient timer that restores it, then changes and
validates the server. The worker confirms over a **new** verified connection under the
mutation lock; when it cannot, the server puts the old configuration back on its own.

Everything here is a fixed command or a fragment of one. Values are validated before they
enter shell text, and the only server-side state is the volatile preimage and the transient
units, never a Barectl record.
"""

import re
import shlex
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from . import native

# docs/adr/0023: policy, five minutes.
WINDOW_SECONDS: Final = 300
WINDOW_MINUTES: Final = WINDOW_SECONDS // 60
PREIMAGE_ROOT: Final = "/run/barectl"
REVERT_PREFIX: Final = "barectl-revert-"
RESTORED_MARKER: Final = "barectl-revert: restored"
# The confirmation script waits for nothing; the revert service is the only waiting
# acquisition of the mutation lock.
LOCK_WAIT_SECONDS: Final = 120
RESTART_SECONDS: Final = 5
# The revert service's restarts after its first start. systemd's StartLimitBurst counts
# every start, so the transient unit allows one more.
RESTART_LIMIT: Final = 3
REVERT_ID_VARIABLE: Final = "BARECTL_REVERT_ID"
_ID = re.compile(r"[0-9a-f]{32}")
_FILE = re.compile(r"/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")


class Window(StrEnum):
    """What native evidence establishes about an open window."""

    KEPT = "kept"
    PUT_BACK = "put_back"
    NOT_KNOWN = "not_known"


@dataclass(frozen=True)
class Names:
    identifier: str
    preimage: str
    timer: str
    service: str
    apply: str

    @property
    def timer_unit(self) -> str:
        return f"{self.timer}.timer"

    @property
    def service_unit(self) -> str:
        return f"{self.service}.service"


def identifier(unit: str) -> str:
    checked = native.check_unit(unit)
    value = checked.removeprefix(native.UNIT_PREFIX).removesuffix(".service")
    if not _ID.fullmatch(value):
        raise ValueError("Not a valid run identifier.")
    return value


def names(unit: str) -> Names:
    """The names one run's window uses, derived from its validated apply unit."""
    value = identifier(unit)
    return Names(
        identifier=value,
        preimage=f"{PREIMAGE_ROOT}/revert-{value}",
        timer=f"{REVERT_PREFIX}{value}",
        service=f"{REVERT_PREFIX}{value}",
        apply=native.check_unit(unit),
    )


def _checked_files(files: tuple[str, ...]) -> tuple[str, ...]:
    for path in files:
        if not _FILE.fullmatch(path) or ".." in path.split("/"):
            raise ValueError("Not a valid preimage file path.")
    return files


def restore_script(files: tuple[str, ...], reload_steps: str) -> str:
    """The transient service's fixed work, run from the saved copy in the preimage.

    It reads the run identifier from the service environment, so the body's bytes stay
    fixed and keep the reviewed digest. It waits for the mutation lock (the only waiting
    acquisition), restores, reloads, and removes the preimage.
    """
    files = _checked_files(files)
    restores = "\n".join(
        f'if [ -e "$revert/{path.rsplit("/", 1)[-1]}" ]; then '
        f'cp -p -- "$revert/{path.rsplit("/", 1)[-1]}" {shlex.quote(path)} || exit 1; '
        f"else rm -f -- {shlex.quote(path)} || exit 1; fi"
        for path in files
    )
    return "\n".join(
        [
            "set -eu",
            "export LC_ALL=C",
            "id=${" + REVERT_ID_VARIABLE + ":?}",
            "revert=" + PREIMAGE_ROOT + "/revert-$id",
            "timer=" + REVERT_PREFIX + "$id.timer",
            "service=" + REVERT_PREFIX + "$id.service",
            'systemctl stop -- "$timer" >/dev/null 2>&1 || true',
            f"d={native.LOCK_DIRECTORY}",
            f"f={native.LOCK_FILE}",
            'mkdir -m 0700 "$d" 2>/dev/null || true',
            "[ \"$(stat -c '%F %u %a' \"$d\")\" = 'directory 0 700' ] || exit 1",
            '[ ! -L "$f" ] || exit 1',
            'exec 9>>"$f" || exit 1',
            "[ \"$(stat -c '%F %u %h' \"$f\")\" = 'regular empty file 0 1' ] || exit 1",
            f"flock -w {LOCK_WAIT_SECONDS} 9 || exit 1",
            '[ -d "$revert" ] || exit 0',
            restores,
            reload_steps,
            'rm -rf -- "$revert"',
            f"printf '%s\\n' {shlex.quote(RESTORED_MARKER)}",
        ]
    )


def save_steps(files: tuple[str, ...], reload_steps: str, *, capture_ufw: bool = True) -> str:
    """Shell body code that saves the preimage and its restore script; uses ``$id``.

    The body sets ``id`` from the run's validated revert identifier argument.
    """
    window_files = _checked_files(files)
    copies = "\n".join(
        f"if [ -e {shlex.quote(path)} ]; then "
        f'cp -p -- {shlex.quote(path)} "$revert/{path.rsplit("/", 1)[-1]}" '
        f"|| refused revert_preimage; "
        f'else : > "$revert/{path.rsplit("/", 1)[-1]}.absent" || refused revert_preimage; fi'
        for path in window_files
    )
    restore = restore_script(window_files, reload_steps)
    steps = [
        "umask 077",
        f"revert={PREIMAGE_ROOT}/revert-$id",
        f"mkdir -p -m 0700 {shlex.quote(PREIMAGE_ROOT)} || refused revert_preimage",
        'rm -rf -- "$revert"',
        'mkdir -m 0700 -- "$revert" || refused revert_preimage',
        copies,
    ]
    if capture_ufw:
        steps.append(
            'if [ "$(ufw status 2>/dev/null | head -n 1)" = "Status: active" ]; then '
            "printf 'yes\\n' > \"$revert/enabled\"; else "
            "printf 'no\\n' > \"$revert/enabled\"; fi"
        )
    steps.extend(
        [
            "cat > \"$revert/restore.sh\" <<'BARECTL_REVERT_RESTORE'",
            restore,
            "BARECTL_REVERT_RESTORE",
            'chmod 0700 -- "$revert/restore.sh" || refused revert_preimage',
            (
                "[ \"$(stat -c '%F %u %a' \"$revert\")\" = 'directory 0 700' ] "
                "|| refused revert_preimage"
            ),
            'chmod 0700 -- "$revert/restore.sh" || refused revert_preimage',
        ]
    )
    return "\n".join(steps)


def arm_step() -> str:
    """Arm ``barectl-revert-<run>.timer`` before the body changes anything; uses ``$id``."""
    return " ".join(
        [
            "/usr/bin/systemd-run",
            f"--unit={REVERT_PREFIX}$id",
            f"--on-active={WINDOW_SECONDS}",
            "--property=Restart=on-failure",
            f"--property=RestartSec={RESTART_SECONDS}",
            f"--property=StartLimitBurst={RESTART_LIMIT + 1}",
            "--property=StartLimitIntervalSec=600",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=60",
            f'--setenv={REVERT_ID_VARIABLE}="$id"',
            "--quiet",
            "--",
            "/usr/bin/sh",
            "-c",
            shlex.quote(f"exec {PREIMAGE_ROOT}/revert-${REVERT_ID_VARIABLE}/restore.sh"),
        ]
    )


def reload_ufw_steps() -> str:
    """Restore the previous firewall state through UFW's own commands only."""
    return (
        'if [ "$(cat "$revert/enabled" 2>/dev/null)" = yes ]; then '
        "ufw reload || exit 1; "
        "else ufw --force disable || exit 1; fi"
    )


def _service_state_steps() -> list[str]:
    """Read the transient service's invocation, control group and journal, without waiting."""
    return [
        'service_state=$(systemctl show -p ActiveState --value "$service" 2>/dev/null || true)',
        'invocation=$(systemctl show -p InvocationID --value "$service" 2>/dev/null || true)',
        'control=$(systemctl show -p ControlGroup --value "$service" 2>/dev/null || true)',
        "populated=0",
        (
            'if [ -n "$control" ]; then '
            'events="/sys/fs/cgroup$control/cgroup.events"; '
            'if [ -r "$events" ] && grep -qx \'populated 1\' "$events"; '
            "then populated=1; fi; fi"
        ),
        'journal=$(journalctl -u "$service" --no-pager -o cat 2>/dev/null || true)',
        'case "$journal" in *'
        + shlex.quote(RESTORED_MARKER)
        + "*) restored=1 ;; *) restored=0 ;; esac",
    ]


def _window_names(unit: str) -> list[str]:
    window = names(unit)
    return [
        f"timer={shlex.quote(window.timer_unit)}",
        f"service={shlex.quote(window.service_unit)}",
        f"revert={shlex.quote(window.preimage)}",
    ]


def confirmation(unit: str) -> list[str]:
    """The fixed confirmation command the worker runs over a new connection under the lock.

    It stops the timer and removes the preimage only when the revert service has no
    invocation and an empty control group. A started revert is left alone.
    """
    started = (
        '[ "$populated" -eq 1 ] || [ "$service_state" = active ] '
        '|| [ "$service_state" = failed ] || [ -n "$invocation" ]'
    )
    result = (
        'if [ "$restored" -eq 1 ] && [ ! -d "$revert" ]; then printf \'put_back\\n\'; '
        "else printf 'not_known\\n'; fi; exit 0"
    )
    steps = [
        "# barectl-revert-confirm",
        "export LC_ALL=C",
        *_window_names(unit),
        *native.lock_steps(
            f"{{ printf 'not_known\\n'; exit {native.Exit.LOCK_CONFLICT}; }}",
            f"{{ printf 'not_known\\n'; exit {native.Exit.LOCK_CONFLICT}; }}",
        ),
        *_service_state_steps(),
        f"if {started}; then {result}; fi",
        'systemctl stop -- "$timer" >/dev/null 2>&1 || true',
        *_service_state_steps(),
        f"if {started}; then {result}; fi",
        'if [ "$restored" -eq 1 ] && [ ! -d "$revert" ]; then printf \'put_back\\n\'; exit 0; fi',
        "rm -rf -- \"$revert\" || { printf 'not_known\\n'; exit 1; }",
        "printf 'kept\\n'",
    ]
    return ["/usr/bin/sh", "-c", "\n".join(steps)]


def evidence_command(unit: str) -> list[str]:
    """Read the window's native evidence without stopping or removing anything."""
    steps = [
        "# barectl-revert-evidence",
        "export LC_ALL=C",
        *_window_names(unit),
        *_service_state_steps(),
        (
            'if [ "$restored" -eq 1 ] && [ ! -d "$revert" ]; then printf \'put_back\\n\'; '
            'elif [ -d "$revert" ] || [ "$populated" -eq 1 ] || [ -n "$invocation" ] '
            '|| [ "$service_state" = active ] || [ "$service_state" = failed ] '
            '|| [ "$(systemctl show -p ActiveState --value "$timer" 2>/dev/null || true)" '
            "= active ]; then printf 'not_known\\n'; fi"
        ),
    ]
    return ["/usr/bin/sh", "-c", "\n".join(steps)]


def parse_window(text: str) -> Window | None:
    value = text.strip()
    for window in Window:
        if value == window.value:
            return window
    return None


def refusal_step(refuse: str) -> str:
    """One preamble step: refuse while a window is armed, its service ran, or a preimage remains."""
    return "; ".join(
        [
            "r=0",
            (
                "for u in $(systemctl list-units --all --plain --no-legend --type=timer "
                "'barectl-revert-*.timer' 2>/dev/null | cut -d' ' -f1); do "
                '[ "$(systemctl show -p ActiveState --value "$u" 2>/dev/null)" = active ] '
                "&& r=1; done"
            ),
            (
                "for u in $(systemctl list-units --all --plain --no-legend --type=service "
                "'barectl-revert-*.service' 2>/dev/null | cut -d' ' -f1); do "
                's=$(systemctl show -p ActiveState --value "$u" 2>/dev/null || true); '
                'case "$s" in active|activating|deactivating|failed) r=1 ;; esac; done'
            ),
            (f'for d in {PREIMAGE_ROOT}/revert-*; do [ -d "$d" ] && r=1; done'),
            f'[ "$r" -eq 0 ] || {{ {refuse}; }}',
        ]
    )
