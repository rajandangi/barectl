"""Read the current release's pending migrations without Artisan (#407).

The Deploy confirm screen offers **Back up first** only when it can see real migration
work: the current release's migration files that the site's migrations table does not
record. Applying still proves the fetched commit's own migrations; this read names the ones
already on disk. This module is composed after ``laravel.bodies.common``, whose helpers it
uses, and is never imported on its own.
"""

import json
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from laravel.bodies.common import (
        MIGRATION_FILE,
        _database_argv,
        current_name,
        laravel_paths,
        user_command,
    )

MAX_PENDING = 64


def pending_read(identifier: str) -> list[str] | None:
    """The current release's pending migration names, or ``None`` when unreadable."""
    name = current_name(identifier)
    if name is None:
        return []
    release = laravel_paths(identifier)[1] / name
    directory = release / "database" / "migrations"
    if release.is_symlink() or not directory.is_dir():
        return []
    files: list[str] = []
    for path in sorted(directory.iterdir()):
        match = MIGRATION_FILE.match(path.name)
        if path.is_file() and match:
            files.append(match.group(1))
    if not files:
        return []
    argv = _database_argv(identifier)
    if argv is None:
        return None
    settings = SimpleNamespace(
        identifier=identifier,
        account="s" + identifier,
        directory="/var/www/" + identifier,
    )
    try:
        records = user_command(settings, [*argv, "SELECT migration FROM migrations"])
    except ValueError:
        return None
    recorded = set(records.split())
    return [item for item in files if item not in recorded][:MAX_PENDING]


if __name__ == "__main__":
    sys.stdout.write(json.dumps(pending_read(sys.argv[1])))
