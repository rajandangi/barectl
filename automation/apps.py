from typing import override

from django.apps import AppConfig


class AutomationConfig(AppConfig):
    name = "automation"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .change import SET_WORDPRESS_SERVER_CRON

        register_kind(SET_WORDPRESS_SERVER_CRON)
