# Upgrading Barectl

This guide moves a Barectl installation on 0.4.x to 1.0 in place. It covers the supported
versions, the stop and backup, the install and migration, post-upgrade verification and
rollback. A database older than 0.4.0 cannot be upgraded this way.

## Supported versions

| From | To | In place |
| --- | --- | --- |
| 0.4.0 and later 0.4.x | 1.0.x | Yes |
| 0.3.x or earlier | 1.0.x | No |

Barectl 0.4.0 replaced the Nginx, Certbot and APT PHP stack and stopped keeping the
migration history of earlier builds. A 0.3.x database therefore has neither the tables nor
the recorded migrations 1.0 expects. The upgrade command refuses it with one sentence.

## Before you start

Run every command from the Barectl checkout on the controller host, as the account that owns
the installation. Two processes use the local database:

- the dashboard (for example `python manage.py runserver`),
- the discovery worker (`python manage.py db_worker`).

Stop both before upgrading. The command also refuses while any change preparation or change
run is queued or running, while the worker still has a queued or running task, or while a
`db_worker` process is alive. Wait for that work to finish; it is recorded work, not
something to discard.

`python manage.py barectl_upgrade --check` reports the installed version and the database
schema without changing anything. Use it first.

## Back up

The upgrade command writes the backup itself, before it runs a migration:

```
upgrade-backups/20261109T120000Z/
├── .env
└── db.sqlite3
```

The timestamp is UTC and the directory is under `settings.BASE_DIR`, beside `db.sqlite3`
and `.env`. The database copy uses SQLite's backup API, so committed write-ahead-log pages
are included. Keep this directory until the upgraded installation has served a few days.

If you prefer a manual copy as well:

```bash
sqlite3 db.sqlite3 ".backup 'db.sqlite3.before-upgrade'"
cp .env .env.before-upgrade
```

## Install the new release

```bash
git fetch --tags
git checkout v1.0.0
uv sync --locked
npm ci
npm run build
```

If you track a branch or use another release channel, check out the revision you intend to
run and run the same install steps. The migration is part of the new code, so install it
before running the upgrade command.

## Migrate

Stop the worker first if it is still running, then:

```bash
uv run --env-file .env python manage.py barectl_upgrade
```

The command:

1. prints the installed version and the database schema;
2. refuses a database older than 0.4.0;
3. refuses while a remote operation, queued task or `db_worker` process is active;
4. writes the timestamped database and `.env` backup and prints its path;
5. applies every pending Django migration;
6. queues a fresh discovery for every saved server;
7. prints the next commands and names any server whose discovery could not be queued.

It never contacts a server itself and writes no marker on a server. Discovery remains an
ordinary read through the existing worker and SSH boundary.

A failed migration is put back from the backup before the command exits, so the original
database is untouched. The error message names the backup directory. Fix the cause, restore
nothing by hand, and run the command again.

## Restart and verify

Start the worker and the dashboard again:

```bash
uv run --env-file .env python manage.py db_worker
uv run --env-file .env python manage.py runserver 127.0.0.1:8000
```

Then:

- sign in and open each server's **Overview**; a queued discovery becomes a fresh snapshot
  with a new collection time;
- check **Activity** for the new discovery attempts;
- confirm the command named no unreadable server, or investigate the ones it named;
- run `python manage.py showmigrations --plan` to confirm no migration is unapplied.

If a server's discovery fails, the upgrade is still complete. The previous snapshot remains
with its notice, and the server page names the connection or permission problem to fix.

## Roll back

Rollback restores the database from before the migration. Stop the dashboard and worker
first, then:

```bash
rm -f db.sqlite3-wal db.sqlite3-shm
cp upgrade-backups/20261109T120000Z/db.sqlite3 db.sqlite3
cp upgrade-backups/20261109T120000Z/.env .env
git checkout v0.4.0
uv sync --locked
npm ci
npm run build
```

Start the 0.4.0 dashboard and worker again. Do not start the older code against the
migrated database: an older release does not know the newer migration records.

## The unsupported 0.3.0 case

A 0.3.x installation cannot be upgraded in place. Start a new 1.0 installation, register
the servers again, and run discovery on each one. Discovery reconstructs the supported
server views from native evidence. It cannot recover the previous installation's Barectl
logins, saved connections, settings or private operation history, and the 0.3.x stack is
not what 1.0 manages. See [reconstruction](architecture.md#state-and-discovery) for what a
fresh controller can and cannot rebuild.

## What the command does not do

- It does not start, stop or reload the dashboard or worker.
- It does not change a managed server, run a change, or write a Barectl file on a server.
- It does not prune old backups; remove them yourself when the upgrade is settled.
- It does not move a remote shared database. The implemented installation database is
  local to the controller host.
