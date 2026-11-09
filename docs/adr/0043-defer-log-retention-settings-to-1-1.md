# Defer journald log-retention settings to 1.1

Accepted on 2026-11-09 for [#530](https://github.com/rajandangi/barectl/issues/530) under the
1.0 specification [#528](https://github.com/rajandangi/barectl/issues/528). It closes the
last Phase E gap named by [logs#later-retention](../logs.md#later-retention) by removing it
from Phase E and 1.0 scope. No application behavior changes.

## Context

Phase E [#301](https://github.com/rajandangi/barectl/issues/301) included a dashboard setting
for journald log retention. [logs](../logs.md) has carried it as "Later" since the Phase E
implementation. The Phase E qualification record names it as outstanding, and the 1.0
specification requires either the setting or a decision that removes it, so the 1.0
contract and qualification record do not inherit an unowned promise.

The foundation already makes the journal persistent and owns
`/etc/systemd/journald.conf.d/50-barectl.conf`. Journal retention is journald's own policy:
`SystemMaxUse`, `MaxRetentionSec`, rotation and vacuuming are native settings that every
Ubuntu administrator can change with `journalctl --vacuum-*` and the journald configuration.
A Barectl setting would need a new reviewed change kind, a reconstruction rule for
externally changed values, a conflict rule against ordinary administration and a native
scenario. None of that is required for a 1.0 compatibility and proof release, and rushing it
would add a new mutation surface immediately before the contract is frozen.

## Decision

Defer journald log-retention settings from Phase E and 1.0 to 1.1. Phase E is complete
without them. The foundation continues to configure a persistent journal; operators manage
retention through journald's documented settings and `journalctl --vacuum-*`. Barectl reads
journals within its existing bounded read limits and never claims to set retention.

The 1.0 qualification record and release notes name the deferral, and the roadmap names 1.1
as the follow-up. The follow-up ticket, when opened, must review a change kind, its discovery
and reconstruction rule, and a native scenario before the setting ships.

## Alternatives considered

- **Ship the setting in 1.0.** Rejected for this release: it needs a new change kind,
  discovery and native proof, and it would enter the frozen contract without a qualification
  lane. The value is operational convenience, not a 1.0 compatibility guarantee.
- **Leave "Later" in the documentation.** Rejected: an unowned promise contradicts the 1.0
  requirement that the documentation have no silent gaps.
- **Remove retention from the roadmap entirely.** Rejected: the Phase E requirement is real
  and should be traced to a later release, not forgotten.

## Consequences

- `docs/logs.md#later-retention` states the deferral and links this record instead of a
  "Later" promise.
- `ROADMAP.md` names 1.1 for journald retention and no longer lists it as outstanding for
  Phase E or 1.0.
- The Phase E qualification record and `docs/v1.0-qualification.md` list it as not qualified
  and deferred, never as passing.
- Operators keep using journald's own configuration and `journalctl --vacuum-*` without a
  Barectl change.

## Sources

- [systemd-journald.conf](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html):
  journal retention is journald's own configured policy.
- [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html):
  the documented `--vacuum-size`, `--vacuum-time` and `--vacuum-files` administration.
- [logs](../logs.md#reading) and [bootstrap](../bootstrap.md): the bounded reads and the
  persistent journal the foundation already owns.
- [Phase E qualification](../phase-e-qualification.md#not-qualified): the existing record of
  the gap this decision closes.
