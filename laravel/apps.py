from typing import override

from django.apps import AppConfig


class LaravelConfig(AppConfig):
    name = "laravel"

    @override
    def ready(self) -> None:
        from operations.engine import register_kind

        from .change import DEPLOY_SITE
        from .create import CREATE_LARAVEL
        from .rollback import ROLLBACK_SITE
        from .settings import EDIT_ENVIRONMENT

        register_kind(CREATE_LARAVEL)
        register_kind(DEPLOY_SITE)
        register_kind(ROLLBACK_SITE)
        register_kind(EDIT_ENVIRONMENT)
