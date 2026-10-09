"""What a stored plan holds, for the tests that prove a value is never kept."""

from django.db.models import Model

from .models import ConfigurationPlan


def kept_text(plan: ConfigurationPlan) -> str:
    """Every value stored for a plan, as text: what could ever be shown."""
    rows: list[Model] = [
        plan,
        *plan.roots.all(),
        *plan.transitions.all(),
        *plan.effects.all(),
        *plan.postconditions.all(),
        *plan.refusals.all(),
        *plan.evidence.all(),
    ]
    return "\n".join(
        str(getattr(row, field.attname)) for row in rows for field in row._meta.concrete_fields
    )
