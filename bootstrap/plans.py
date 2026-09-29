"""Only this module writes plan rows, and nothing updates a plan once stored.

docs/adr/0005-review-exact-bootstrap-transitions.md
"""

from datetime import datetime, timedelta

from django.db.models import Prefetch, QuerySet

from .models import (
    ADMISSION_CENTISECONDS,
    ConfigurationPlan,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanNativeUnit,
    PlanPostcondition,
    PlanPreparation,
    PlanRefusal,
    PlanRootPackage,
    Privilege,
)
from .profiles import PROFILE_REVISION
from .review import Draft

ADMISSION_WINDOW = timedelta(seconds=ADMISSION_CENTISECONDS / 100)


def save_plan(
    preparation: PlanPreparation, draft: Draft, *, host_key: str, collected_at: datetime
) -> ConfigurationPlan:
    """Call inside the transaction that marks ``preparation`` succeeded."""
    platform = draft.platform
    uptime = platform.uptime_centiseconds if platform else None
    plan = ConfigurationPlan.objects.create(
        preparation=preparation,
        action=draft.action,
        profile_revision=PROFILE_REVISION,
        intent=draft.intent,
        eligible=draft.eligible,
        no_changes=draft.no_changes,
        ssh_alias=preparation.ssh_alias,
        host_key=host_key,
        boot_id=platform.boot_id if platform else "",
        uptime_centiseconds=uptime,
        admission_deadline_centiseconds=None if uptime is None else uptime + ADMISSION_CENTISECONDS,
        collected_at=collected_at,
        admission_expires_at=collected_at + ADMISSION_WINDOW,
        os_name=platform.os.pretty_name if platform else "",
        release=draft.release.version if draft.release else "",
        architecture=platform.architecture if platform else "",
        apt_version=platform.tools.get("apt", "") if platform else "",
        dpkg_version=platform.tools.get("dpkg", "") if platform else "",
        systemd_version=platform.tools.get("systemd", "") if platform else "",
        privilege=platform.privilege if platform else Privilege.UNAVAILABLE,
    )
    PlanRootPackage.objects.bulk_create(
        PlanRootPackage(plan=plan, name=root.name, version=root.version, installed=root.installed)
        for root in draft.roots
    )
    PackageTransition.objects.bulk_create(
        PackageTransition(
            plan=plan,
            position=position,
            step=transition.step,
            package=transition.package,
            architecture=transition.architecture,
            version=transition.version,
            origins="\n".join(transition.origins),
        )
        for position, transition in enumerate(draft.transitions)
    )
    PlanEffect.objects.bulk_create(
        PlanEffect(plan=plan, position=position, kind=kind, text=text)
        for position, (kind, text) in enumerate(draft.effects)
    )
    PlanPostcondition.objects.bulk_create(
        PlanPostcondition(plan=plan, position=position, text=text)
        for position, text in enumerate(draft.postconditions)
    )
    PlanRefusal.objects.bulk_create(
        PlanRefusal(plan=plan, position=position, reason=reason, text=text)
        for position, (reason, text) in enumerate(draft.refusals)
    )
    PlanEvidence.objects.bulk_create(
        PlanEvidence(plan=plan, kind=item.kind, fingerprint=item.fingerprint, summary=item.summary)
        for item in draft.evidence
    )
    PlanNativeUnit.objects.bulk_create(
        PlanNativeUnit(
            plan=plan,
            position=position,
            unit_name=unit.unit,
            invocation_id=unit.invocation_id,
            active_state=unit.active_state,
            sub_state=unit.sub_state,
            result=unit.result,
            exec_main_status=unit.exec_main_status,
        )
        for position, unit in enumerate(draft.units)
    )
    return plan


def with_plans(preparations: QuerySet[PlanPreparation]) -> QuerySet[PlanPreparation]:
    related = (
        "roots",
        "transitions",
        "effects",
        "postconditions",
        "refusals",
        "evidence",
        "native_units",
    )
    return preparations.select_related("server", "plan").prefetch_related(
        *(Prefetch(f"plan__{name}") for name in related)
    )
