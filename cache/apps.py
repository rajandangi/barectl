from typing import override

from django.apps import AppConfig


class CacheConfig(AppConfig):
    name = "cache"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .engine import INSTALL

        register_kind(INSTALL)
