from typing import override

from django.apps import AppConfig


class BackupsConfig(AppConfig):
    name = "backups"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from . import check  # noqa: F401 - registers the backup check step
        from .change import BACK_UP_FULL, BACK_UP_NOW, ENABLE
        from .connect import CONNECT
        from .keys import REPLACE
        from .offsite import COPY, REMOVE, SET_UP
        from .reopen import REOPEN_SITE
        from .restore import RESTORE
        from .retention import DISABLE, KEEP, SET
        from .schedule import SET_BACKUP_SCHEDULE

        register_kind(ENABLE)
        register_kind(BACK_UP_NOW)
        register_kind(BACK_UP_FULL)
        register_kind(REOPEN_SITE)
        register_kind(SET_UP)
        register_kind(REMOVE)
        register_kind(COPY)
        register_kind(CONNECT)
        register_kind(REPLACE)
        register_kind(RESTORE)
        register_kind(SET)
        register_kind(DISABLE)
        register_kind(KEEP)
        register_kind(SET_BACKUP_SCHEDULE)
