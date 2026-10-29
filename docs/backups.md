# Backups (implemented, #396, #399, #400 and #403)

Each managed site gains a **Backups** section between Overview and Activity. It shows
whether the site is backed up, its last safe result, its offsite copy result and its recovery
points. The planned Phase D behaviour, including schedules, retention, restoring files and
export, is the [Phase D specification](https://github.com/rajandangi/barectl/issues/358);
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
native lock, so a slow upload never lengthens downtime and never races another copy. A failed
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

## Restore database only

Each listed **database-only** or **full site** recovery point offers **Restore** for its
database. It is one reviewed **Destructive** change with a typed confirmation of the
site's primary domain. The review names the exact recovery point and target site, what is
replaced (the site's own database; other sites' databases are not touched), the matching
site kind and database engine major, the free disk it keeps, and the expected downtime. It
says whether a safety backup will be taken: an empty target skips it and the review says so.

Applying re-lists the point under the site's `.deploy.lock` and refuses a missing,
incomplete or different-engine-major copy before the site is touched. When the target holds
data it takes and verifies a database-only safety backup first. It then pauses and drains
the site exactly as a full capture does, replaces the site's own database with the point's
data and verifies three findings separately:

- the import finished;
- the data checks passed (the database holds the tables the point contained);
- the site answered its readiness check through its private admission path.

The database import streams `restic dump` into the site's own engine client as the site's
Linux user over the local socket, as the `s<id>` principal, never a superuser, and needs no
network when the point is onsite. Only after all three findings does the gate open and the
site's background work resume. A restore that stops partway stays gated with one sentence
and **Reopen site**, exactly like an interrupted full capture; **Check what happened**
inspects the original run and never submits it again. Restoring files only, full-site
restores, cross-server restores and exporting a point remain planned.

## Restic results

Restic's exit codes map to the engine's result classes: `0` succeeded, `3` partial (a
snapshot was saved, some data was unreadable), `10` refused (repository missing), `11` a
skipped run (lock failed), `12` refused (wrong password), and any other code failed. A dump
failure is refused with `backup_dump` and leaves no snapshot.

Every capture writes one final safe `barectl-result` line with its result class, counts,
bytes, a short point identifier and its offsite outcome (`copied`, `failed`, or empty when
offsite storage is not set up). `Copy offsite again` writes its own `kind:"copy"` line, so
discovery keeps the copy result apart from the capture result. A full capture first writes a `backup_paused` line so
discovery can name a capture that was interrupted; the engine ignores that interim line and
reads only the final outcome. Neither line carries a path, repository URL, credential or
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

## Native evidence

The checked-in body is `backups/bodies/enable.py` for setup, `backups/bodies/backup.py` for
a database-only capture, `backups/bodies/full.py` for a paused full capture,
`backups/bodies/restore.py` for a database restore and `backups/bodies/reopen.py` for
reopening a paused site; each prints its stages and a result line. The pause helpers shared by
the full capture and the restore are `backups/bodies/paused.py`. The read is
`backups/bodies/observe.py`, shared with the database binding's pure catalog reader. The first
shared Phase D native scenario is `disposable/test_backups.py`.
On the local ubuntu-26.04 lane it measured 62 to 65 s for the `BackupLifecycle` test
(69 to 72 s for the scenario including lane setup), including a full capture and a killed
capture that stays gated until **Reopen site**; the breadth-only reboot proof measured
65.3 s for the test and 70 s for its scenario. The local full build measured 294 s against the 300 s target and
900 s limit (controller-fast 46 s, browser 94 s, native 294 s). The same build's
fast-validator stage measured 79 s against the 60 s joint-fast target, a validator-stage
miss already named in the [Phase C qualification record](phase-c-qualification.md), not a
new native item from this slice.
