"""docs/dashboard-workflows.md#site-pages"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

from django.db.models import Q

from bootstrap.apply import apply_history
from bootstrap.models import Action
from bootstrap.presentation import ApplyView, PreparationView
from bootstrap.services import preparation_history
from tls.installation import STAGES
from tls.models import CertificateInstallation, CertificateInstallationStep

from .models import Server

# docs/dashboard-workflows.md#site-pages: the typed requests and the runs' retained copies
# that record a site's identifier.
_SITE_REQUESTS = (
    "site_request",
    "database_request",
    "tls_request",
    "staging_request",
    "issuance_request",
    "activation_request",
    "wordpress_request",
    "installation_request",
    "finish_request",
    "inspection_request",
    "maintenance_request",
)
_RUN_SITES = (
    "site",
    "binding",
    "challenge",
    "staging",
    "issuance",
    "activation",
    "wordpress_runtime",
    "wordpress_install",
    "wordpress_finish",
    "wordpress_inspection",
    "wordpress_maintenance",
)
_SITE_ACTIONS = (
    Action.SITE_HTTP,
    Action.DATABASE_MARIADB,
    Action.DATABASE_POSTGRESQL,
    Action.TLS_CHALLENGE,
    Action.TLS_READINESS,
    Action.TLS_STAGING,
    Action.TLS_ISSUANCE,
    Action.TLS_ACTIVATION,
    Action.PHP_WORDPRESS,
    Action.WORDPRESS_INSTALL,
    Action.WORDPRESS_FINISH,
    Action.WORDPRESS_INSPECT,
    Action.WORDPRESS_MAINTAIN,
)
UNKNOWN_STEP = "Unrecognized step"


@dataclass(frozen=True)
class InstallationStepView:
    label: str
    preparation_id: int | None
    run_id: int | None


@dataclass(frozen=True)
class InstallationView:
    installation_id: int
    status_label: str
    created_at: datetime
    finished_at: datetime | None
    failure: str
    steps: list[InstallationStepView]


@dataclass(frozen=True)
class SiteActivity:
    operations: list[PreparationView | ApplyView]
    installations: list[InstallationView]


def _naming(prefix: str, relations: Iterable[str], identifier: str) -> Q:
    condition = Q()
    for relation in relations:
        condition |= Q(**{f"{prefix}{relation}__identifier": identifier})
    return condition


def site_activity(server: Server, identifier: str, shown: Sequence[str]) -> SiteActivity:
    """``server``'s operations of the ``shown`` actions recorded for ``identifier``."""
    installations = list(
        CertificateInstallation.objects.filter(server=server, identifier=identifier)
        .prefetch_related("steps")
        .order_by("-created_at", "-pk")
    )
    steps = [step for installation in installations for step in installation.steps.all()]
    operations: list[PreparationView | ApplyView] = [
        *preparation_history(
            shown,
            server,
            (Q(action__in=_SITE_ACTIONS) & _naming("", _SITE_REQUESTS, identifier))
            | Q(pk__in=[step.preparation_id for step in steps if step.preparation_id]),
        ),
        *apply_history(
            shown,
            server,
            (
                Q(action__in=_SITE_ACTIONS)
                & (
                    _naming("plan__preparation__", _SITE_REQUESTS, identifier)
                    | _naming("", _RUN_SITES, identifier)
                )
            )
            | Q(pk__in=[step.run_id for step in steps if step.run_id]),
        ),
    ]
    operations.sort(key=lambda row: (row.queued_at, row.operation_id), reverse=True)
    if not set(STAGES) <= set(shown):
        return SiteActivity(operations, [])
    return SiteActivity(operations, [_installation(item) for item in installations])


def _step_label(step: CertificateInstallationStep) -> str:
    if 0 <= step.position < len(STAGES):
        return STAGES[step.position].label
    return UNKNOWN_STEP


def _installation(installation: CertificateInstallation) -> InstallationView:
    return InstallationView(
        installation_id=installation.pk,
        status_label=installation.get_status_display(),
        created_at=installation.created_at,
        finished_at=installation.finished_at,
        failure=installation.failure,
        steps=[
            InstallationStepView(_step_label(step), step.preparation_id, step.run_id)
            for step in installation.steps.all()
        ],
    )
