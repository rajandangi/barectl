from typing import override

from django.apps import AppConfig


class LogsConfig(AppConfig):
    name = "logs"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from . import services  # noqa: F401 - registers the log-read step
        from .change import SET_UP_LOG_ROTATION
        from .journal_retention_change import SET_JOURNAL_RETENTION

        register_kind(SET_UP_LOG_ROTATION)
        register_kind(SET_JOURNAL_RETENTION)
