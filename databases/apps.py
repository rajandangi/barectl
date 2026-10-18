from typing import override

from django.apps import AppConfig


class DatabasesConfig(AppConfig):
    name = "databases"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .engine import INSTALL, REMOVE

        register_kind(INSTALL)
        register_kind(REMOVE)
