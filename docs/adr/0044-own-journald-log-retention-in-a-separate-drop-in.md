# Own journald log retention in a separate drop-in

Accepted on 2026-11-13 for [#548](https://github.com/rajandangi/barectl/issues/548), the 1.1
follow-up to [ADR 0043](0043-defer-log-retention-settings-to-1-1.md). It adds the dashboard
retention setting that ADR 0043 deferred from Phase E and 1.0. It does not change the
foundation's persistent-storage setting or add a second execution path.

## Context

The host foundation already owns `/etc/systemd/journald.conf.d/50-barectl.conf` and writes
`Storage=persistent`. Journal retention is journald's own policy: `SystemMaxUse` caps disk
usage, `MaxRetentionSec` bounds the age of archived journal files, and `journalctl
--vacuum-*` reclaims space immediately. ADR 0043 deferred a dashboard setting to 1.1 because
it would need a reviewed change kind, a reconstruction rule for externally changed values, a
conflict rule against ordinary administration and a native scenario.

systemd merges every `/etc/systemd/journald.conf.d/*.conf` file in lexicographic order, and a
later file overrides an earlier one for the same key. An operator may already have added a
later drop-in, or may hand-edit any file in that directory. The setting therefore has to
name one file Barectl owns and must not claim a policy that another file overrides.

## Decision

Barectl owns a second drop-in, `/etc/systemd/journald.conf.d/60-barectl-log-retention.conf`,
as `root:root 0644`, containing one `[Journal]` section with `SystemMaxUse` and
`MaxRetentionSec`. The foundation keeps `50-barectl.conf` and `Storage=persistent`; the
`60-` name sorts after it and overrides only the two retention keys.

The setting is one reviewed **Shared** change with two fixed choices written together. It
writes the file atomically, reads the merged configuration and refuses a later override,
restarts `systemd-journald.service`, reads both effective values back and restores the
previous state on failure. It never runs `journalctl --vacuum-*`, so it deletes no log history and does not
need Destructive consent.

Discovery reads the file state and both effective values from one fixed read and reports
exactly one state:

- **Not configured** when the file is absent;
- **Managed** only when the file is exactly the rendered pair at `root:root 0644` and both
  effective values equal it; or
- **Outside supported settings** for a hand edit, a wrong owner, group or mode, a missing or
  extra line, or a later drop-in that overrides either effective value.

Barectl never adopts or overwrites an outside file. Deleting the file by hand returns the
setting to Not configured; a manual vacuum changes no configuration and leaves a managed
setting managed.

The native contract gains the new path, shape, URL and result vocabulary. The contract moves
to the next version the pinned history test requires (2 with the current tree) because a
1.0.1 result reader cannot safely ignore a new change kind and reason, even though every
version-1 native shape is unchanged. No native migration is needed; the upgrade notes make a
controller upgrade a prerequisite for mixed-version use.

## Alternatives considered

- **Extend `50-barectl.conf`.** Rejected: the foundation and the retention change would own
  one file. The foundation's contract content, review disclosure and digest would change,
  and reconstruction could not tell which kind edited which line.
- **Write a `99-barectl-retention.conf` file.** Rejected: it would override every ordinary
  administrator drop-in by default. A `60-` file states Barectl's ownership without claiming
  to be the last word; a later administrator file still wins and becomes outside supported
  settings.
- **Adopt a hand-written file whose effective values match.** Rejected: a rewrite could
  remove comments or unrelated lines, and Barectl could not know what the operator intended.
- **Vacuum to the new cap during apply.** Rejected: it destroys retained audit history,
  forces Destructive consent and widens the mutation surface. Journald reclaims space under
  its own policy, and `journalctl --vacuum-*` remains the operator's immediate tool.
- **Free-text sizes and ages.** Rejected: invalid or dangerous values are easy to type, and
  a fixed list keeps the review, reconstruction and tests small.

## Consequences

- A later drop-in that overrides either value is reported as outside supported settings and
  blocks only this setting. The operator resolves it through ordinary administration.
- The setting is server-wide, so it lives in Server Settings and a site's Logs section only
  points to it.
- `journalctl --vacuum-*` stays documented and unwrapped; Barectl never deletes logs.
- A 1.0.1 controller reports the server outside supported settings after a 1.1 change and
  refuses further changes. The upgrade notes tell operators to upgrade every controller
  before using the setting.
- `docs/logs.md` replaces the "Later: retention" section, `docs/settings.md` describes the
  card, and `docs/contracts.md` moves to version 2 with the new shape.

## Sources

- [journald.conf](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html):
  `SystemMaxUse`, `MaxRetentionSec` and the drop-in merge order.
- [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html):
  the documented `--vacuum-size`, `--vacuum-time` and `--vacuum-files` administration.
- [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html):
  lexicographic drop-in precedence under `*.conf.d/`.
- [ADR 0042](0042-version-the-native-contract-without-a-server-marker.md): additive changes
  may keep a version only when the previous reader ignores them safely.
- [ADR 0043](0043-defer-log-retention-settings-to-1-1.md) and [logs](../logs.md): the
  deferral this record closes.
