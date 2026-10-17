from typing import override

from django.apps import AppConfig


class LaravelConfig(AppConfig):
    name = "laravel"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .change import DEPLOY_SITE
        from .rollback import ROLLBACK_SITE

        register_kind(DEPLOY_SITE)
        register_kind(ROLLBACK_SITE)
