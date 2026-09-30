"""Only this module writes a database plan's own rows, in the transaction that saves the plan."""

from bootstrap.models import ConfigurationPlan

from . import binding
from .admission import BindingDraft
from .drivers import DriverDraft
from .inspection import InspectionDraft
from .models import (
    PlanCatalogObservation,
    PlanDatabaseBinding,
    PlanDatabaseStatement,
    PlanDriverPool,
)


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


def save_binding(plan: ConfigurationPlan, draft: BindingDraft) -> None:
    if not draft.eligible or draft.release is None:
        return
    name = draft.principal
    probe = binding.render_probe(draft.engine, name, draft.token)
    PlanDatabaseBinding.objects.create(
        plan=plan,
        identifier=draft.identifier,
        engine=draft.engine,
        php_version=draft.release.php,
        site_user=name,
        uid=draft.uid,
        gid=draft.gid,
        principal=name,
        database=name,
        authentication=binding.authentication_text(draft.engine),
        character_set=binding.character_set(draft.engine),
        collation=binding.collation(draft.engine, draft.locale),
        engine_version=draft.engine_version,
        driver_version=draft.driver_version,
        other_engine=draft.other_engine,
        probe_token=draft.token,
        probe_path=binding.probe_path(draft.identifier, draft.token),
        probe_content=probe,
        probe_sha256=binding.digest(probe),
        payload_bytes=draft.payload_bytes,
    )
    PlanDatabaseStatement.objects.bulk_create(
        PlanDatabaseStatement(
            plan=plan,
            position=position,
            step=statement.step.value,
            database=statement.database,
            text=statement.text,
        )
        for position, statement in enumerate(draft.statements)
    )


def save_inspection(plan: ConfigurationPlan, draft: InspectionDraft) -> None:
    PlanCatalogObservation.objects.bulk_create(
        PlanCatalogObservation(
            plan=plan,
            position=position,
            identifier=identifier,
            engine=database.engine or "",
            status=database.outcome,
            conforms=database.conforms,
            principal=database.principal,
            database=database.database,
            authentication=database.authentication,
            privileges=database.privileges,
            character_set=database.character_set,
            collation=database.collation,
            owner=database.owner,
            warning=database.warning,
        )
        for position, (identifier, database) in enumerate(draft.observations)
    )
