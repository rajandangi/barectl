from typing import override

from django.apps import AppConfig


class DatabasesConfig(AppConfig):
    name = "databases"

    @override
    def ready(self) -> None:
        from bootstrap.actions import register_handler

        from .handler import BINDINGS, DRIVERS, INSPECTION

        for handler in (DRIVERS, BINDINGS, INSPECTION):
            register_handler(handler)
