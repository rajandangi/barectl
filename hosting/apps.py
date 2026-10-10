from typing import override

from django.apps import AppConfig


class HostingConfig(AppConfig):
    name = "hosting"

    @override
    def ready(self) -> None:
        from operations.lifecycle import register_completion

        from .creation import completed

        register_completion(completed)
