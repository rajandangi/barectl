from typing import override

from django.apps import AppConfig


class WordPressConfig(AppConfig):
    name = "wordpress"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .create import CREATE_WORDPRESS

        register_kind(CREATE_WORDPRESS)
