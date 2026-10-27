# Backups (implemented, #396)

Each managed site gains a **Backups** section between Overview and Activity. It shows
whether the site is backed up, its last safe result, and its recovery points. The planned
Phase D behaviour, including schedules, retention, restores, offsite storage and export, is
the [Phase D specification](https://github.com/rajandangi/barectl/issues/358); this page
describes only what is built.

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

A site without a site database cannot be enabled yet: this slice captures databases only.

## Back up now, Database only

**Back up now** is one reviewed Site change. It streams the site's dump straight into the
encrypted repository with restic's `--stdin-from-command`, run as the site's own Linux user
over the local socket:

- MariaDB: `mariadb-dump --single-transaction --quick --no-tablespaces --routines --events
  --triggers s<id>`;
- PostgreSQL: `pg_dump --no-owner --no-privileges s<id>`.

A failed dump makes restic cancel the backup and create no snapshot, so nothing is listed as
a recovery point. No plain-text dump is written to disk. The capture never pauses the site,
holds the site's `.deploy.lock`, and checks that at least 1 GiB is free on the repository filesystem before it starts;
shortage refuses the capture and deletes nothing.

Restic's exit codes map to the engine's result classes: `0` succeeded, `3` partial (a
snapshot was saved, some data was unreadable), `10` refused (repository missing), `11` a
skipped run (lock failed), `12` refused (wrong password), and any other code failed. A dump
failure is refused with `backup_dump` and leaves no snapshot.

Every capture writes one safe `barectl-result` line with its result class, counts, bytes and
a short point identifier. It never carries a path, repository URL, credential or dump
content.

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

The checked-in body is `backups/bodies/enable.py` for setup and
`backups/bodies/backup.py` for a capture; both print their stages and one result line. The
read is `backups/bodies/observe.py`, shared with the database binding's pure catalog reader.
The first shared Phase D native scenario is `disposable/test_backups.py`. On the local
ubuntu-26.04 lane it measured 40.1 s for the one test and 47 s for the scenario including
lane setup, inside the 180 s item limit. The local full build measured 264 s against the
300 s target and 900 s limit.
