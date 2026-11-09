# v0.4.0 database fixture

`v0.4.0.sqlite` is a populated Barectl application database recorded from the `v0.4.0`
tag. `dashboard/test_upgrade.py` copies it, applies every later migration with Django's
`MigrationExecutor`, and asserts that each represented record and relationship survives.
A migration that drops, renames or truncates one of those records fails the fast gate.

The file is not under a `fixtures/` directory because every file under one is recorded
from a real server ([coding standards](../../CODING_STANDARDS.md)); this is a database
recorded from a tag, not native server output. It uses the `.sqlite` extension because
`.gitignore` ignores `*.sqlite3`.

## Regenerating

The recorder is the only supported way to regenerate the fixture:

```bash
uv run --env-file .env python scripts/record-v040-database-fixture.py
```

It creates a detached temporary `git worktree` at `v0.4.0`, runs that tree's
`manage.py migrate` against its own `db.sqlite3`, seeds the rows below through an inline
Django shell script, copies the database here, and removes the worktree. It then prints
the recorded migration set, which must stay equal to `V040_MIGRATIONS` in
`dashboard/upgrade.py`.

The tag pins Django 6.1.1 and django-tasks-db 0.13.0, the same releases this checkout
uses, so the recorder runs the tag's migrations with the current development Python
rather than creating a second virtual environment. A future lock change means installing
the tag's pinned dependencies first.

## What it represents

- one operator account in the Administrator preset
- one saved server connection revision and its server
- one succeeded discovery attempt with a snapshot and one setting observation
- one succeeded change preparation, its review, and the run that applied it
- the Viewer, Site operator and Administrator groups with their permissions

## Limits

- It proves local database migration only. It says nothing about a managed server's state.
- Regenerating changes the file bytes because passwords are salted and timestamps are
  recorded; review the new fixture rather than expecting a stable binary.
- Do not hand-edit the database. Add a representative row to the recorder's seed script
  and regenerate.
- The upgrade command never reads this fixture at runtime. Detection uses the sentinel
  migrations in `dashboard/upgrade.py`, and tests use the file.
