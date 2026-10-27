from typing import override

from django.apps import AppConfig


class BackupsConfig(AppConfig):
    name = "backups"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from . import check  # noqa: F401 - registers the backup check step
        from .change import BACK_UP_NOW, ENABLE

        register_kind(ENABLE)
        register_kind(BACK_UP_NOW)
