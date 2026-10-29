# Backups (implemented, #396, #399, #400, #401, #402, #403, #404 and #405)

Each managed site gains a **Backups** section between Overview and Activity. It shows
whether the site is backed up, its last safe result, its offsite copy result and its recovery
points. The planned Phase D behaviour, including retention, restoring files and export, is the [Phase D specification](https://github.com/rajandangi/barectl/issues/358);
this page describes only what is built.

## Offsite storage

Server **Settings > Backup storage** connects one bucket on **Amazon S3** or **Cloudflare
R2**. There is no free-form endpoint and no other provider. The setup review is one Shared
change that also needs **manage secrets**. It checks the bucket can be written and listed
before saving, and then:

- writes the access keys to root-only environment files on the server, never to Barectl's
  database;
- initialises each backed-up site's offsite repository under one fixed server prefix with
  restic's `--copy-chunker-params`, so a copy deduplicates;
- adds the recovery passphrase as a key to each offsite repository, so the kit, the
  passphrase and the provider keys open the copies after the server and controller are both
  gone;
- is idempotent: reviewing the same provider, bucket, region and endpoint again changes
  nothing.

On S3 an optional separate pruning key can be stored; captures and copies then use the other
key, which cannot delete offsite history. On R2 the review says plainly that an Object Read &
Write token can also delete objects. The review also says that neither S3 Object Lock nor R2
bucket locks are configured, so offsite copies are not immutable.

**Remove offsite storage** is one reviewed Shared change that also needs **manage secrets**.
It removes the setting and its keys from the server and deletes no offsite copy: everything
already in the bucket stays there, and the review says so.

### Captures and copies

A capture whose site has offsite storage copies its onsite point after the site has reopened
(or, for Database only, after the onsite point is verified). The copy holds a per-repository
native lock and releases the shared mutation and site locks once the onsite point is safe, so
a slow upload never lengthens downtime, never races another copy and never blocks hosting
changes. A failed
copy keeps the onsite point unchanged and the Backups section says **Saved here, offsite copy
failed.** Onsite and offsite results are shown separately.

**Copy offsite again** on a recovery point is one reviewed Site change that copies that exact
point without taking a new capture. It initialises the offsite repository first when it is
missing, and it is the repair action for a failed upload.

## Offsite paths

| Part | Path | Owner and mode |
| --- | --- | --- |
| Offsite setting | `/etc/barectl/backups/offsite/config` | root `0600` |
| Capture and copy keys | `/etc/barectl/backups/offsite/capture.env` | root `0600` |
| Optional S3 pruning keys | `/etc/barectl/backups/offsite/prune.env` | root `0600` |

The repository URL is `s3:<endpoint>/<bucket>/<prefix>/<site>` and the fixed prefix is stored
in the setting, so a fresh controller reconstructs it. Discovery reads only the non-secret
fields and whether each key file is present; it never reads a key value or contacts the
bucket. A setting outside the supported template is reported once and blocks only backup
changes for the sites.

## Enable backups

**Enable backups** is one reviewed Shared change that also needs **manage secrets**. It:

- realises restic 0.18.1 from the pinned catalog lock and sets the
  `/nix/var/nix/profiles/barectl/restic` profile;
- creates `/var/lib/barectl-backups/<id>/onsite`, a root-only repository outside every
  site's files;
- initialises the repository with the operator's **recovery passphrase**, then adds a random
  **server key** in `/etc/barectl/backups/<id>.key`, so both the passphrase and the key open
  it and plain `restic` needs only the passphrase;
- shows the printable **recovery kit**, which names the server, the repository and the plain
  restic commands and holds no secret.

The passphrase is typed on the confirmation screen and travels only through the confidential
input channel ([ADR 0032](adr/0032-keep-secrets-in-private-native-files.md)). It is never
stored and never shown again. Barectl refuses to apply the review until the operator also
ticks that they stored the passphrase and the kit away from the server and Barectl.

A site without a site database can be enabled now: **Database only** stays unavailable with
its reason, and **Back up now** copies the site's files as a full point without a database
part.

## Back up now

**Back up now** is one reviewed Site change with two choices.

### Database only

The dump streams straight into the encrypted repository with restic's
`--stdin-from-command`, run as the site's own Linux user over the local socket:

- MariaDB: `mariadb-dump --single-transaction --quick --no-tablespaces --routines --events
  --triggers s<id>`;
- PostgreSQL: `pg_dump --no-owner --no-privileges s<id>`.

A failed dump makes restic cancel the backup and create no snapshot, so nothing is listed as
a recovery point. No plain-text dump is written to disk. The capture never pauses the site,
holds the site's `.deploy.lock`, and checks that at least 1 GiB is free on the repository filesystem before it starts.

### Full site

A full capture pauses only the site for an exact point. It holds `.deploy.lock`, fences the
site's background work, publishes the site's maintenance gate, drains the site's private
HAProxy admission and waits for every FPM worker to be Idle, then writes two snapshots that
share one `--time` and point identifier:

- the database stream, when the site has a site database;
- the site's current release and its private state: Laravel's `.env`, `storage/` and
  `bootstrap/cache`, WordPress's private configuration, and the current release for plain
  PHP.

Both parts are tagged `complete` only after both are verified present. The gate opens only
then, and the site's background work starts again only after the reviewed open site
configuration is published and verified. **Excluded** are the object cache's (Valkey) data,
logs, sockets, sessions, temporary files, other retained releases, runtime builds, the deploy
key and known-hosts, and web server, proxy, PHP and TLS state.

The review names the pause, the copy and the exclusions, and its consent follows the gate:
Site when this is the server's only site, Shared when Caddy reloads for other sites. Free
disk below the reserved headroom refuses the capture; a capture that runs out while copying
stops with a warning and never deletes an older point. A half point, such as a database
snapshot whose files part failed, is listed as **Incomplete**, names the missing part and is
never restorable.

### When a full capture stops

A capture killed after the gate, or interrupted by a reboot, leaves the gate in place. The
Backups section and the site's Overview show **"This stopped after pausing the site for a
full backup. Nothing after it ran."** with one action, **Reopen site**. Reopening is one
reviewed Site change (Shared when other sites exist) that publishes the site's reviewed open
Caddy file. It never starts background work: Scheduled tasks or Queue workers ask what should
run again, so a half-migrated or half-copied site is never served with its work resumed
unreviewed.

## Schedule

Each site has at most one **schedule**, created and turned off only through a reviewed
Site change. It chooses **daily** or **weekly** (Monday) at an explicit `HH:MM` in UTC, a
scope (**Database only** or **Full site**) and whether to copy the point offsite. An offsite
schedule is refused until offsite storage is set up; the copy then runs after the onsite
point is complete and holds only the repository lock. New sites start with no schedule;
enabling backups does not create one.

The schedule is a fixed native timer in the site's own backup slice, separate from its
automation slice:

- `barectl-site-<id>-backup.slice`, `.service` and `.timer`;
- the service is a oneshot with a finite two-hour run window and no restart;
- the timer sets `Persistent=false` (no catch-up), `AccuracySec=1s`,
  `RandomizedDelaySec=0` and `DeferReactivation=yes`, and names its UTC calendar explicitly.

A tick runs a fixed rendered body, not a change-engine run. It takes the global native lock
with a bounded wait, then the site's `.deploy.lock`; when either is held it records a
**skipped** run and exits, and a skip is never shown as a saved point. The capture is
**live**: the database first, then the files, tagged `capture:live` and `origin:scheduled`,
and never pauses the site. A full point is tagged complete only after both parts are
verified present. The same body does not catch up: a missed window is missed.

The review refuses a window that overlaps another site's window on the same server (a
window is the hour the run starts in) and names the next free hour. The next run is shown
only when systemd reports it; the page never invents a schedule. A fresh controller
reconstructs the schedule and its next run from the units, the runtime payload and systemd
during **Check backups** and every schedule review. An installed unit whose settings differ
from the fixed template is **Outside supported settings**, is reported once, and blocks only
that site's backup changes.

Every change that names a site treats that site's running backup unit as busy, so a Deploy,
PHP switch or restore never races a capture. Turning the schedule off stops and disables the
timer, stops the service and slice, and removes the unit files and runtime payload.

## Restore

Each listed recovery point offers **Restore** with the scopes its point supports: **Database
only**, **Files only** (from a full point) and **Full site**. It is one reviewed
**Destructive** change with a typed confirmation of the site's primary domain. The review
names the exact recovery point and target site, what is replaced, the matching site kind and
database engine major, the free disk it keeps, and the expected downtime. A live recovery
point's review says its files and database may differ by the capture window. **Files only**
warns that the database is left as it is now, so files and database then come from different
points.

The safety backup matches the restore's scope: Database only, Files only or Full site. An
empty target database skips it for a Database only restore and the review says so; a files or
full restore always takes a paused safety point first.

Applying re-lists the point under the site's `.deploy.lock` and refuses a missing, incomplete
or different-engine-major copy before the site is touched. Files are downloaded into a private
root-only staging directory and admitted there: absolute or traversing paths, links outside
the convention's own, device files, FIFOs, sockets, setuid and setgid files are all refused
while the site still runs. The site is then paused and drained exactly as a full capture does.

- **Files** become a new release directory in #356's site-owned release form, owned by the
  target site user whatever the archive recorded. Root performs only the `current` switch,
  as Deploy does. The release that was serving stays
  retained, and the restored release counts toward Deploy's retention of `current` plus five. Laravel's shared `.env`, `storage/` and
  `bootstrap/cache` are replaced as a whole, not overlaid. WordPress's private configuration
  file is replaced but the target's own database settings in it are kept, because the site
  database is always `s<id>`.
- **Permissions** are re-applied from the convention, never taken from the archive. For
  Laravel and plain PHP only `current/public` is readable by `caddy`, and PHP source stays the
  site user's. For WordPress the files are group-readable by `caddy` and never world-readable,
  and the private configuration file is 0600.
- **The database** is imported by streaming `restic dump` into the site's own engine client as
  the site's Linux user over the local socket, as the `s<id>` principal, never a superuser.
- **Native configuration** (the Caddy site file, HAProxy and PHP-FPM) is re-rendered from the
  convention, never from the archive. Restore never runs application code, Artisan, WP-CLI,
  migrations, key generation or dependency downloads, and needs no network when the point is
  onsite.

Verification keeps three findings apart:

- the restore finished (the files are the current release and the import completed);
- the data checks passed (the database holds the tables the point contained and the restored
  release is complete);
- the site answered its readiness check through its private admission path.

Only after all three does the gate open and the site's background work resume. A restore that
stops partway stays gated with one sentence and **Reopen site**, exactly like an interrupted
full capture; **Check what happened** inspects the original run and never submits it again.
Cross-server restores and exporting a point remain planned.

## Retention

**Keep backups for** offers 1 week, 2 weeks, 3 weeks, 1 month or 6 months. No policy exists
until an operator reviews one; 1 week is preselected only when the site has no policy yet.
**Set retention** is one reviewed **Destructive** change. Its review runs
`restic forget --dry-run --json` against fresh onsite and offsite listings and lists every
recovery point the policy would delete now, with its time, scope and location, and says that
deletion is permanent. Applying installs the site's cleanup units and deletes nothing itself.

Cleanup runs daily onsite and weekly offsite as fixed native units in the site's backup slice.
Each run first requires a synchronized clock from `timedatectl`; otherwise it skips with that
reason. For each location, scope and part it runs `restic forget` filtered by the Barectl
marker and `complete` tag, with `--group-by ''`, `--keep-within <period>d`, `--keep-last 1` and
`--keep-tag keep`, and then `prune`. Because full points share one capture time, their parts
expire together. Untagged or hand-made snapshots are reported and never touched, and onsite
and offsite results are computed independently.

Before forgetting in a scope, cleanup restore-reads the newest complete point there (offsite
uses its weekly read-back). If the read fails, everything in that scope is kept and reported.
The newest readable point per scope and location is always kept. A held per-repository lock is
a skip, never a success; restic's own stale-lock rule applies and Barectl never runs
`unlock --remove-all`.

Every cleanup run writes one `barectl-result` line with `deleted`, `kept`, `skipped` and
`failed` point counts per location, plus the `foreign` snapshots it left alone. It carries no
path, repository URL, credential or dump content.

**Turn retention off** is one reviewed Site change. It removes the cleanup units and stops
them; it deletes no recovery point.

## Integrity

Enabling backups installs one weekly integrity unit per repository, onsite and offsite, in
the site's backup slice. Each run holds the per-repository native lock, runs `restic check`
with a rotating `--read-data-subset`, and reads the newest complete recovery point back with
`restic dump` through a private staging directory. The subset advances on every recorded run and
covers the whole repository over twenty weeks; the result line names the subset that ran.

The integrity finding is its own row per site and location, with its time. It is shown apart
from the capture result, the offsite copy result and the recovery-point list. **Verified**
means Barectl itself opened the newest point: a successful `restic snapshots` listing, or
exit status 0 from the repository check alone, never marks a point verified. A corrupted pack
is reported as an integrity failure. It changes no snapshot or capture, and the capture
result stays as it was.

A held per-repository lock or an offsite store that is not set up yet is a skip, never a
success. Every run writes one `barectl-result` line with its class, location, counts, bytes,
short point identifier and subset. It carries no path, repository URL, credential or dump
content.

## Keep

**Keep** on a recovery point is one reviewed Site change that toggles the point's `keep` tag
and changes no other tag. It never deletes a snapshot. Retention's `--keep-tag keep` then
preserves the point until it is unkept. Keeping a point uses only the onsite repository, so it
never needs offsite credentials.

## Restic results

Restic's exit codes map to the engine's result classes: `0` succeeded, `3` partial (a
snapshot was saved, some data was unreadable), `10` refused (repository missing), `11` a
skipped run (lock failed), `12` refused (wrong password), and any other code failed. A dump
failure is refused with `backup_dump` and leaves no snapshot.

Every capture writes one final safe `barectl-result` line with its result class, counts,
bytes, a short point identifier and its offsite outcome (`copied`, `failed`, or empty when
offsite storage is not set up). `Copy offsite again` writes its own `kind:"copy"` line, so
discovery keeps the copy result apart from the capture result. A full capture first writes a
`backup_paused` line so discovery can name a capture that was interrupted; the engine ignores
that interim line and reads only the final outcome. Neither line carries a path, repository URL, credential or
dump content.

## Check backups

**Check backups** is an explicit authorized read through the worker. It runs
`restic snapshots --json --no-lock` with the site's server key and stores the bounded,
Barectl-tagged listing on its request row with the time it was read. It never changes the
repository and never authorizes a restore. Opening the Backups section makes no SSH
connection. A listing older than 15 minutes is labelled as possibly out of date.

## Discovery

Passive discovery reads the restic profile, each site's root-only repository and server key,
whether the site database exists, and the newest safe `barectl-result` line in the journal.
It runs no restic command, lists no snapshots and contacts no storage. A fresh controller
reconstructs that backups are enabled and the last result from this native evidence alone.

## Paths

| Part | Path | Owner and mode |
| --- | --- | --- |
| Onsite repository | `/var/lib/barectl-backups/<id>/onsite` | root, directory `0700`, `config` `0400` or `0600` |
| Server key | `/etc/barectl/backups/<id>.key` | root `0600` |
| restic profile | `/nix/var/nix/profiles/barectl/restic` | root, the pinned catalog build |
| restic cache | `/var/cache/barectl/restic` | root `0700` |
| Retention body and payload | `/etc/barectl/backups/retention/<id>.sh`, `<id>.json` | root `0600`, directory `0700` |
| Cleanup units | `/etc/systemd/system/barectl-site-<id>-cleanup.service` and `.timer`, plus `-cleanupoffsite.service` and `.timer` | root-owned fixed templates |
| Integrity units | `/etc/systemd/system/barectl-site-<id>-check.service` and `.timer`, plus `-checkoffsite.service` and `.timer` | root-owned fixed templates |
| Integrity body and payload | `/etc/barectl/backups/integrity/<id>.sh`, `<id>.json` | root `0700` script, `0600` payload |

## Native evidence

The checked-in body is `backups/bodies/enable.py` for setup, `backups/bodies/backup.py` for
a database-only capture, `backups/bodies/full.py` for a paused full capture,
`backups/bodies/restore.py` for Database only, Files only and Full site restores, `backups/bodies/offsite.py` for offsite
storage, `backups/bodies/copy.py` for Copy offsite again, `backups/bodies/reopen.py` for
reopening a paused site, `backups/bodies/schedule.py` for the schedule install and its live
tick, `backups/bodies/retention.py` for retention cleanup, Keep and their unit templates, and
`backups/bodies/integrity.py` for the weekly check; each prints its stages and a result line.
The integrity run is appended to the Enable backups body, so the check script is the reviewed
body itself. The schedule read is
`backups/bodies/observe_schedule.py`. Passive discovery reads the newest integrity result
lines for each location and stores them as typed `BackupIntegrity` rows; Check backups
refreshes them with one bounded journal read. The pause helpers shared by
the full capture and the restore are `backups/bodies/paused.py`. The read is
`backups/bodies/observe.py`, shared with the database binding's pure catalog reader. The first
shared Phase D native scenario is `disposable/test_backups.py`; its offsite checks use a
local S3-compatible fixture (`disposable/native_mirror/s3.py`) in its own lane container and
never the internet. The #401 files-only and full-site restore assertions and the #405 integrity
assertions extend the same scenario; the integration run records their measured addition. On the local ubuntu-26.04 lane it measured 62 to 65 s for the `BackupLifecycle` test
(69 to 72 s for the scenario including lane setup), including a full capture and a killed
capture that stays gated until **Reopen site**; the breadth-only reboot proof measured
65.3 s for the test and 70 s for its scenario. The local full build measured 294 s against the 300 s target and
900 s limit (controller-fast 46 s, browser 94 s, native 294 s). The same build's
fast-validator stage measured 79 s against the 60 s joint-fast target, a validator-stage
miss already named in the [Phase C qualification record](phase-c-qualification.md), not a
new native item from this slice.
