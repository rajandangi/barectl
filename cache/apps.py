from typing import override

from django.apps import AppConfig


class CacheConfig(AppConfig):
    name = "cache"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from . import reading  # noqa: F401 - registers the cache reading step
        from .engine import INSTALL
        from .instance import SET_SITE_OBJECT_CACHE

        register_kind(INSTALL)
        register_kind(SET_SITE_OBJECT_CACHE)
