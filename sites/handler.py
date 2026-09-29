"""The HTTP site action's place in configuration plans (bootstrap.actions)."""

import secrets
from dataclasses import dataclass

from bootstrap.actions import Authority
from bootstrap.models import Action, ConfigurationPlan, PlanPreparation
from bootstrap.review import Draft
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import admission, inspection
from .models import SiteRequest
from .plans import save_site
from .presentation import SiteReview, site_review

_VIEW = ("servers.view_server", "sites.view_siteplan")
AUTHORITY = Authority(
    view=_VIEW,
    prepare=(*_VIEW, "sites.prepare_siteplan"),
    apply=(*_VIEW, "sites.apply_siteplan"),
)
MISSING_REQUEST = (
    "The site request of this preparation is not recorded, so Barectl did not connect."
)


@dataclass(frozen=True)
class SiteHandler:
    actions: frozenset[str] = frozenset({Action.SITE_HTTP})
    authority: Authority = AUTHORITY
    # docs/sites.md#applying: not offered until its own journey is qualified.
    applicable: bool = False
    review_template: str = "sites/_site_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        request = SiteRequest.objects.filter(preparation=preparation).first()
        if request is None:
            raise OperationRefused(MISSING_REQUEST)
        names = tuple(request.names.splitlines())
        token = secrets.token_hex(16)
        evidence = inspection.inspect(shell, request.identifier, token)
        return admission.review(request.identifier, names, token, evidence)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, admission.SiteDraft):
            save_site(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("site", "site_names", "site_files", "site_directories", "site_account")

    def review(self, plan: ConfigurationPlan) -> SiteReview | None:
        return site_review(plan)


HANDLER = SiteHandler()
