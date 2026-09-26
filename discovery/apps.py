import logging
import sys
from typing import override

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class DiscoveryConfig(AppConfig):
    name = "discovery"

    @override
    def ready(self) -> None:
        # Restarting the worker must not leave servers permanently busy. When this
        # process is the durable worker, recover interrupted attempts before polling.
        if "db_worker" not in sys.argv:
            return
        try:
            from .services import recover_stale_attempts

            recover_stale_attempts()
        except Exception as error:
            # Startup recovery is best-effort: tables may not exist yet during install.
            logger.warning("Discovery recovery on worker startup skipped: %s", type(error).__name__)
