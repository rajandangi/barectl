"""The HTTP site action's place in configuration plans (bootstrap.actions)."""

import secrets
from dataclasses import dataclass

from bootstrap.actions import Authority
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanPreparation,
    Verification,
)
from bootstrap.native import UnitEvidence
from bootstrap.review import Draft
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import admission, apply, inspection
from . import names as site_names
from .models import SiteRequest
from .plans import save_site
from .presentation import SiteReview, site_review

_VIEW = ("servers.view_server", "sites.view_siteplan")
AUTHORITY = Authority(
    view=_VIEW,
    prepare=(*_VIEW, "sites.prepare_siteplan"),
    apply=(*_VIEW, "sites.apply_siteplan"),
)
INVALID_REQUEST = (
    "The stored site request is not a valid identifier and set of names, so Barectl read "
    "nothing from the server. Prepare a new site plan."
)
MISSING_REQUEST = (
    "The site request of this preparation is not recorded, so Barectl read nothing from the server."
)


@dataclass(frozen=True)
class SiteHandler:
    actions: frozenset[str] = frozenset({Action.SITE_HTTP})
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "sites/_site_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        request = SiteRequest.objects.filter(preparation=preparation).first()
        if request is None:
            raise OperationRefused(MISSING_REQUEST)
        try:
            identifier, names = site_names.request(
                request.identifier, " ".join(request.names.splitlines())
            )
        except site_names.InvalidInput:
            raise OperationRefused(INVALID_REQUEST) from None
        token = secrets.token_hex(16)
        evidence = inspection.inspect(shell, identifier, token)
        return admission.review(identifier, names, token, evidence)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, admission.SiteDraft):
            save_site(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("site", "site_names", "site_files", "site_directories", "site_account")

    def review(self, plan: ConfigurationPlan) -> SiteReview | None:
        return site_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return apply.payload(run, plan)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return apply.verification_failure(run)


HANDLER = SiteHandler()
