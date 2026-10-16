# Use native bootstrap execution and exclusion

> Amended by [ADR 0032](0032-keep-secrets-in-private-native-files.md): a fixed command on the same connection may stage a secret from standard input for the payload to consume. [ADR 0035](0035-one-change-engine-with-effect-derived-consent.md) owns the result-line contract and the change kinds that use this execution.

Every change submits one finite payload to a uniquely named transient systemd system service, which owns execution after the controller disconnects. Every payload acquires the same nonblocking native flock before validating its boot identity, admission deadline, the other Barectl units and its reviewed evidence. Pyinfra's shell interface, through the connection `discovery/ssh.py` opens, carries staging, submission and inspection; neither a controller worker nor a local database lock owns remote execution or cross-device exclusion. `operations/native.py` builds the submission, lock steps, inspection and closure probe, and `operations/engine.py` builds each run's payload around its kind's body.

## Submission

`systemd-run --unit=barectl-apply-<32 hex digits>.service --description='Barectl reviewed apply' --quiet --expand-environment=no --service-type=exec --collect -p ExitType=cgroup -p Restart=no -p RuntimeMaxSec=30min -p TimeoutStopSec=60 -p KillMode=control-group -p StandardInput=null -p StandardOutput=journal -p StandardError=journal /usr/bin/sh -c <payload>`, run as root or through `sudo -n` after `sudo -n -l` authorized that exact command line. No `--scope`, `--pty`, `--pipe` or `--wait`; systemd-run returns once the main process was executed, and the SSH connection owns nothing of the unit. The unit name is saved locally when the run is queued. Payloads over 16 KiB are refused, never split. A kind may set native limits on the unit (`LimitFSIZE`, `MemoryMax` and `MemorySwapMax=0`) as further `--property` arguments of the same reviewed command line. `--expand-environment=no` appears as the `no-env-expand` flag of `ExecStartEx` on systemd 259, and `%` is not expanded in transient command lines.

`--collect` makes systemd unload the unit when it ends, even after a failure, so a run's outcome lives in the journal's `barectl-result` line, which the foundation's persistent journal keeps across reboots. Units left loaded by other means are still counted and can be cleared by a reviewed cleanup.

## Staged bodies

A kind's body is a checked-in script. Before submission, a fixed root command writes it from the SSH connection's standard input to `/run/lock/barectl/body-<32 hex digits>.sh`; the body's bytes never appear in argv, unit properties or the journal. The payload refuses unless the staged file's SHA-256 is the digest the review recorded, then runs it with `exec` in the same shell, which holds the lock on descriptor 9 for every child. The payload's exit trap removes the staged file on every path. The staging area is volatile and is not an operation journal or inventory.

## Payload

Fixed shell text with validated parameters, each step in the foreground:

1. Create `/run/lock/barectl` with mode 0700 if missing, and refuse unless it is a root-owned directory with mode 0700 (`/run/lock` is world-writable, so another user could have created it). Refuse a symlinked lock file; open `/run/lock/barectl/mutation.lock` for appending, which never truncates or replaces it, and refuse unless it is an empty root-owned regular file with one link. It holds no data.
2. `flock -n` on descriptor 9, which children inherit. There is no waiting or lock stealing; a held lock reports `lock_busy`.
3. Under the lock: the boot ID must equal the reviewed one, `/proc/uptime` must be before the deadline, no other `barectl-apply-*.service` control group may report `populated 1` (a child can close the lock descriptor and outlive its wrapper), the retained Barectl units must be below the kind's capacity (100, or 110 for a cleanup), the affected sites of a Shared review must match their reviewed digest, `apt-daily`, `apt-daily-upgrade` and `unattended-upgrades` must have no processes, and the staged body must have its reviewed digest. Each failure reports `refused` with its reason before any change.
4. The kind's body rechecks its own reviewed evidence and makes the change. It prints one `barectl-stage <name>` line per stage and ends with one `barectl-result` line whose class is `succeeded`, `refused`, `partial`, `failed`, `lock_busy` or `timed_out`.

Simultaneous submissions from independent controllers can both refuse: each one's unit exists while the other checks for processes. Neither waits; each needs a new review.

## Inspection and outcomes

Inspection reads the boot ID, `systemctl show` of `Id`, `LoadState`, `ActiveState`, `SubState`, `Result`, `ExecMainCode`, `ExecMainStatus` and `InvocationID`, and `populated` from the unit's `cgroup.events`, all unprivileged. The kernel removes only an empty control group, so a `cgroup.events` that is absent, or that disappears while it is read as the unit exits, reports no processes; one present without a `populated` line leaves the evidence unreadable. While the unit runs, the engine reads its stage lines from the journal. Once systemd has unloaded it, the engine reads the run's `barectl-result` line with `journalctl -u <unit>`, waiting briefly for the journal to publish it. `Result=timeout` is a timeout, and a killed main process is a termination.

Verification is separate: each kind's verification reads the server again after a successful result, and a run succeeds only when both hold. A terminal run whose verification cannot be read closes as failed with verification unavailable and keeps its execution outcome.

Acknowledgement is not evidence. The worker records the dispatch before sending; a lost answer, lost connection, unreadable evidence, a missing result line, a run still active after the watch limit, or a stopped worker leaves the run reconciling, and Check outcome inspects the same unit name and journal with a new connection, requiring the recorded invocation once known. Nothing is ever submitted again, resumed or replayed.

## Unknown outcomes

A run with neither a loaded unit nor a result line, after a reboot or a journal loss, stays reconciling as outcome unknown; their absence is never taken as proof that it did not run. An operator with the permission to apply the run's change may acknowledge it, which asks one check to close it. That check runs a finite probe, `/usr/bin/sh -c <probe>` as root or through `sudo -n` after `sudo -n -l` authorized exactly it, directly over the connection rather than as a unit, so nothing is retained. The probe takes the mutation lock the same way every payload does, without waiting, and while holding it prints the boot ID, the monotonic uptime, the number of Barectl units with processes and the run's `LoadState`. The run closes as failed with outcome unknown only when the lock was taken, the boot changed or the uptime reached the run's deadline, no Barectl unit has processes, the unit is still absent, and the acknowledging account is still active and allowed. Otherwise it stays reconciling with the missing proof. A delayed delivery of the old payload then refuses its boot or deadline under the lock before any change.

## Consequences

- Native service state and the journal's result line are the only execution evidence; reviews and audit records stay in the application database. Journal retention is the operating system's; the foundation makes it persistent, and a run whose result line was rotated away before Barectl read it stays unknown.
- Exclusion holds between controllers with independent databases and keys submitting together: at most one change runs (native scenario S10). An administrator's own commands that do not take the lock remain outside the guarantee.
- Transient units and the lock directory do not survive a reboot; nothing resumes, and a run caught by one closes only as outcome unknown.
- Clearing retained units removes evidence another installation may still need; that installation can then only close its run as outcome unknown. The cleanup review says so.
- Upstream sources: systemd 259 [systemd-run](https://raw.githubusercontent.com/systemd/systemd/v259/man/systemd-run.xml), [systemd.service](https://raw.githubusercontent.com/systemd/systemd/v259/man/systemd.service.xml), [systemd.kill](https://raw.githubusercontent.com/systemd/systemd/v259/man/systemd.kill.xml) and [systemctl](https://raw.githubusercontent.com/systemd/systemd/v259/man/systemctl.xml); util-linux 2.39.3 [flock](https://raw.githubusercontent.com/util-linux/util-linux/v2.39.3/sys-utils/flock.1.adoc); [sudo-rs(8)](https://manpages.ubuntu.com/manpages/resolute/man8/sudo-rs.8.html) for `-n -l`. That a collected transient unit is forgotten and that a descendant killed after a zero main exit leaves `Result=success` are Barectl's observations of systemd 259, not upstream guarantees.
