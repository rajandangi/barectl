from typing import override

from django.apps import AppConfig


class WordPressConfig(AppConfig):
    name = "wordpress"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .actions import RESET_PASSWORD, VERIFY_CORE
        from .create import CREATE_WORDPRESS

        register_kind(CREATE_WORDPRESS)
        register_kind(RESET_PASSWORD)
        register_kind(VERIFY_CORE)
