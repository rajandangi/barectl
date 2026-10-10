from typing import override

from django.apps import AppConfig


class BootstrapConfig(AppConfig):
    name = "bootstrap"

    @override
    def ready(self) -> None:
        # Importing the service modules registers the plan preparation and apply steps.
        from . import apply, runtime_changes, services  # noqa: F401
        from .actions import register_handler
        from .runtime_handler import HANDLER

        register_handler(HANDLER)
