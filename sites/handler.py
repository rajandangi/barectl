"""The HTTP site action's place in configuration plans (bootstrap.actions)."""

import secrets
from dataclasses import dataclass

from django.urls import reverse

from bootstrap.actions import Authority, Completion
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
from servers.discovery_state import server_state, site_page

from . import admission, apply, inspection
from . import names as site_names
from .models import PlanSite, SiteRequest
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

    def audit(self, run: ApplyRun) -> list[str]:
        return apply.audit(run)

    def completion(self, run: ApplyRun) -> Completion | None:
        """The site's page once the run is verified, or why it is not current yet."""
        if run.verification != Verification.PASSED or run.plan is None:
            return None
        try:
            identifier = run.plan.site.identifier
        except PlanSite.DoesNotExist:
            return None
        server = run.server
        if server is None:
            return None
        state = server_state(server)
        page = site_page(state, identifier)
        if page.site is not None:
            domains = ", ".join(page.site.domains) or identifier
            collected = state.snapshot.collected_at if state.snapshot is not None else None
            observed_at = f" at {collected:%b %d, %Y, %H:%M:%S %Z}" if collected is not None else ""
            return Completion(
                url=reverse("site_detail", args=[server.pk, identifier]),
                label=f"Open site {domains}",
                observed=True,
                note=f"Observed as a current site{observed_at}.",
            )
        return Completion(
            url=reverse("server_detail", args=[server.pk]),
            label="Open the server to refresh observations",
            observed=False,
            note=(
                "The run is verified, but the current observation does not show this site yet. "
                "Refresh the connection before treating it as a current site."
            ),
        )


HANDLER = SiteHandler()
