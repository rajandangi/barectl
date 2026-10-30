"""Native process admission for distribution package services."""

import shlex
from typing import Final

PROCESS_PROBE: Final = """for unit in apt-daily.service apt-daily-upgrade.service; do
report=$(systemctl show --property=LoadState --property=ControlGroup "$unit") || exit 2
load=$(printf '%s\\n' "$report" | sed -n 's/^LoadState=//p')
case "$load" in loaded|not-found|masked) ;; *) exit 2 ;; esac
cg=$(printf '%s\\n' "$report" | sed -n 's/^ControlGroup=//p')
[ -n "$cg" ] || cg="/system.slice/$unit"
case "$cg" in /system.slice/*) ;; *) exit 2 ;; esac
case "$cg" in *..*|*' '*|*'
'*) exit 2 ;; esac
events="/sys/fs/cgroup$cg/cgroup.events"
[ -e "$events" ] || continue
[ -r "$events" ] || exit 2
grep -qx 'populated 1' "$events" && exit 1
grep -qx 'populated 0' "$events" || exit 2
done
exit 0"""

PROCESS_COMMAND: Final = shlex.join(["/usr/bin/sh", "-c", PROCESS_PROBE])
