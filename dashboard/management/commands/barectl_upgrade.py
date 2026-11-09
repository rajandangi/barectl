from typing import override

from django.core.management.base import BaseCommand, CommandError, CommandParser

from dashboard import upgrade


class Command(BaseCommand):
    help = (
        "Back up this installation, migrate its local database in place, and queue a fresh "
        "discovery for every saved server."
    )

    @override
    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--check",
            action="store_true",
            help="Report the installed version and schema state, then stop.",
        )

    @override
    def handle(self, *args: object, **options: object) -> None:
        environment = upgrade.default_environment()
        self.stdout.write(f"Installed version: {environment.installed_version()}")
        self.stdout.write(f"Database schema: {environment.schema_state().describe()}")
        try:
            outcome = upgrade.perform_upgrade(
                check_only=bool(options.get("check", False)), environment=environment
            )
        except upgrade.UpgradeRefused as refused:
            raise CommandError(str(refused)) from refused
        if outcome.backup is None:
            self.stdout.write("The database schema is already up to date; nothing to do.")
            return
        self.stdout.write(f"Backup written to {outcome.backup}")
        if outcome.queued:
            names = ", ".join(server.name for server in outcome.queued)
            self.stdout.write(f"Queued a fresh discovery for {names}.")
        else:
            self.stdout.write("No saved servers need a fresh discovery.")
        for server, reason in outcome.unreadable:
            self.stdout.write(
                f"Could not queue discovery for {server.name} ({reason}); check it in the "
                "dashboard."
            )
        self.stdout.write("Next:")
        self.stdout.write("  uv run --env-file .env python manage.py db_worker")
        self.stdout.write(
            "  Open the dashboard and check each server's Overview shows a new discovery."
        )
