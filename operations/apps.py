import sys
from typing import override

from django.apps import AppConfig


class OperationsConfig(AppConfig):
    name = "operations"

    @override
    def ready(self) -> None:
        # Importing these modules registers the change engine's kinds and steps.
        from . import cleanup, confidential, engine

        engine.register_kind(cleanup.CLEANUP_RUNS)
        # A worker process mints a fresh sealing key at start, so a value sealed for an
        # earlier worker can no longer be opened and its run fails as expired
        # (docs/adr/0032-keep-secrets-in-private-native-files.md).
        if "db_worker" in sys.argv:
            confidential.rotate()
