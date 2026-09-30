"""Only this module writes a database plan's own rows, in the transaction that saves the plan."""

from bootstrap.models import ConfigurationPlan

from .drivers import DriverDraft
from .models import PlanDriverPool


def save_driver(plan: ConfigurationPlan, draft: DriverDraft) -> None:
    PlanDriverPool.objects.bulk_create(
        PlanDriverPool(
            plan=plan,
            position=position,
            name=pool.name,
            user=pool.user,
            socket=pool.socket,
            default=pool.default,
        )
        for position, pool in enumerate(draft.pools)
    )
