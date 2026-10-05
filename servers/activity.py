"""A managed server's and a site's local operation history (docs/dashboard-workflows.md).

Rows belong to the server registration through its foreign key, never through a matching
name or SSH alias, so detached audit never joins a later registration.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

from django.db.models import Q, QuerySet

from bootstrap.models import ApplyRun, PlanPreparation
from bootstrap.plans import with_plans
from bootstrap.presentation import ApplyView, PreparationView, apply_view, view
from operations.lifecycle import recovers_first
from tls.installation import STAGES
from tls.models import CertificateInstallation

from .models import Server

type OperationView = PreparationView | ApplyView

# The typed requests that name a site, by their relation from a preparation. A driver,
# inspection or renewal setup request records an empty identifier and names no site.
_SITE_REQUESTS = (
    "site_request",
    "database_request",
    "tls_request",
    "staging_request",
    "issuance_request",
    "activation_request",
)
# Each run's retained copy of the site it changes, kept after its plan is deleted.
_RUN_SITES = ("site", "binding", "challenge", "staging", "issuance", "activation")


@dataclass(frozen=True)
class InstallationStepView:
    label: str
    preparation_id: int | None
    run_id: int | None


@dataclass(frozen=True)
class InstallationView:
    installation_id: int
    status_label: str
    active: bool
    created_at: datetime
    finished_at: datetime | None
    failure: str
    steps: list[InstallationStepView]


@dataclass(frozen=True)
class SiteActivity:
    operations: list[OperationView]
    installations: list[InstallationView]


def _newest_first(
    preparations: QuerySet[PlanPreparation], runs: QuerySet[ApplyRun]
) -> list[OperationView]:
    rows: list[OperationView] = [view(preparation) for preparation in with_plans(preparations)]
    rows.extend(apply_view(run) for run in runs)
    return sorted(rows, key=lambda row: (row.queued_at, row.operation_id), reverse=True)


@recovers_first
def server_operations(server: Server, shown: Sequence[str]) -> list[OperationView]:
    """The registration's preparations and apply runs of the ``shown`` actions."""
    preparations = PlanPreparation.objects.filter(server=server, action__in=shown)
    runs = ApplyRun.objects.filter(server=server, action__in=shown)
    return _newest_first(preparations, runs)


def _naming(prefix: str, relations: Iterable[str], identifier: str) -> Q:
    condition = Q()
    for relation in relations:
        condition |= Q(**{f"{prefix}{relation}__identifier": identifier})
    return condition


@recovers_first
def site_activity(server: Server, identifier: str, shown: Sequence[str]) -> SiteActivity:
    """The registration's operations recorded for ``identifier``, of the ``shown`` actions.

    The association is the typed request, the run's retained copy or a certificate
    installation's step, never intent prose; it says nothing about the current site.
    """
    if not identifier:
        return SiteActivity([], [])
    installations = list(
        CertificateInstallation.objects.filter(server=server, identifier=identifier)
        .prefetch_related("steps")
        .order_by("-created_at", "-pk")
    )
    steps = [step for installation in installations for step in installation.steps.all()]
    preparations = PlanPreparation.objects.filter(server=server, action__in=shown).filter(
        _naming("", _SITE_REQUESTS, identifier)
        | Q(pk__in=[step.preparation_id for step in steps if step.preparation_id])
    )
    runs = ApplyRun.objects.filter(server=server, action__in=shown).filter(
        _naming("plan__preparation__", _SITE_REQUESTS, identifier)
        | _naming("", _RUN_SITES, identifier)
        | Q(pk__in=[step.run_id for step in steps if step.run_id])
    )
    operations = _newest_first(preparations, runs)
    if not set(STAGES) <= set(shown):
        return SiteActivity(operations, [])
    return SiteActivity(operations, [_installation(item) for item in installations])


def _installation(installation: CertificateInstallation) -> InstallationView:
    steps = [
        InstallationStepView(
            label=STAGES[step.position].label,
            preparation_id=step.preparation_id,
            run_id=step.run_id,
        )
        for step in installation.steps.all()
    ]
    return InstallationView(
        installation_id=installation.pk,
        status_label=installation.get_status_display(),
        active=installation.status == CertificateInstallation.Status.ACTIVE,
        created_at=installation.created_at,
        finished_at=installation.finished_at,
        failure=installation.failure,
        steps=steps,
    )
