from typing import override

from django.apps import AppConfig


class OperationsConfig(AppConfig):
    name = "operations"

    @override
    def ready(self) -> None:
        # Importing these modules registers the change engine's kinds and steps.
        from . import cleanup, engine

        engine.register_kind(cleanup.CLEANUP_RUNS)
