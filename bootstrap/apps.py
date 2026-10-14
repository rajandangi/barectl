from typing import override

from django.apps import AppConfig


class BootstrapConfig(AppConfig):
    name = "bootstrap"

    @override
    def ready(self) -> None:
        # Importing the service modules registers the plan preparation and apply steps.
        # ADRs 0006 and 0035: old-stack runs share the unit namespace and lock until Phase A
        # removes them, so engine cleanup excludes their active units.
        from operations.engine import register_active_units, register_kind

        from . import apply, services  # noqa: F401
        from .foundation import HOST_FOUNDATION

        register_kind(HOST_FOUNDATION)
        register_active_units(self._active_units)

    @staticmethod
    def _active_units() -> frozenset[str]:
        from operations.models import RemoteOperation

        from .models import ApplyRun

        return frozenset(
            ApplyRun.objects.filter(status__in=RemoteOperation.ACTIVE).values_list(
                "unit_name", flat=True
            )
        )
