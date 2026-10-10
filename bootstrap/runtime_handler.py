"""PHP default changes use the existing reviewed plans and native admission."""

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from bootstrap.actions import BOOTSTRAP, Authority
from databases.drivers import Pool
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import (
    apply,
    inspection,
    native,
    php_supply,
    php_trust,
    profiles,
    releases,
    runtime_native,
    runtime_services,
)
from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from .review import Draft, check_platform, review
from .runtime_models import RuntimePlan, RuntimeRequest, RuntimeRun, RuntimeSelection


@dataclass
class RuntimeDraft(Draft):
    branch: str = ""
    before_branch: str = ""
    before_mode: str = ""
    default_digest: str = ""
    source_digest: str = ""
    package_action: str = ""
    identifier: str = ""
    old_branch: str = ""
    old_revision: int = 4
    site_digest: str = ""
    old_site: str = ""
    new_site: str = ""
    old_pool: str = ""
    new_pool: str = ""
    names: str = ""
    token: str = ""
    body_sha256: str = ""
    database_engine: str = ""
    database_digest: str = ""
    driver_pools: tuple[Pool, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DefaultHandler:
    actions: frozenset[str] = frozenset({Action.PHP_DEFAULT})
    authority: Authority = BOOTSTRAP
    applicable: bool = True
    review_template: str = "bootstrap/_plan_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> RuntimeDraft:
        request = RuntimeRequest.objects.filter(preparation=preparation).first()
        if (
            request is None
            or request.branch not in php_supply.ELIGIBLE_BRANCHES
            or request.identifier
        ):
            raise OperationRefused("The PHP default request is missing or invalid.")
        reader = inspection.Reader(shell)
        platform = inspection.read_platform(reader)
        release = releases.of(platform.os) if platform is not None else None
        draft = RuntimeDraft(
            Action.PHP_DEFAULT,
            f"Set the server PHP default to {request.branch}.",
            platform,
            release,
            branch=request.branch,
        )
        check_platform(draft, platform)
        observed = runtime_services.observe_php_runtime(shell)
        if observed.failure:
            draft.refuse(PlanRefusal.Reason.INCOMPLETE, observed.failure)
            return draft
        draft.php_supply = observed.supply or "ubuntu"
        draft.php_version = request.branch
        draft.default_digest = observed.fingerprint
        if observed.default is not None:
            draft.before_branch = observed.default.branch
            draft.before_mode = observed.default.mode
        if release is None or platform is None:
            return draft
        _validate_source(draft, shell)
        if request.branch not in observed.installed and draft.eligible:
            return installation_draft(shell, draft, Action.PHP)
        if draft.eligible:
            if (
                observed.default is not None
                and observed.default.branch == request.branch
                and observed.default.mode == "manual"
            ):
                draft.effects.append(
                    (
                        PlanEffect.Kind.NO_CHANGES,
                        "The requested native default is already selected.",
                    )
                )
            else:
                draft.effects.append(
                    (
                        PlanEffect.Kind.SITE_FILES,
                        (
                            "Change the native php alternative; "
                            "pinned site pools retain their branches."
                        ),
                    )
                )
        return draft

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if not isinstance(draft, RuntimeDraft):
            raise OperationRefused("The runtime review is missing.")
        RuntimePlan.objects.create(plan=plan, **selection_values(draft))
        if draft.driver_pools:
            from databases.models import PlanDriverPool

            PlanDriverPool.objects.bulk_create(
                PlanDriverPool(
                    plan=plan,
                    position=position,
                    name=pool.name,
                    user=pool.user,
                    socket=pool.socket,
                    default=pool.default,
                )
                for position, pool in enumerate(draft.driver_pools)
            )

    def prefetch(self) -> tuple[str, ...]:
        return ("runtime",)

    def review(self, plan: ConfigurationPlan) -> RuntimePlan | None:
        return RuntimePlan.objects.filter(plan=plan).first()

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        selection = self.review(plan)
        return (
            ""
            if selection is None
            else (
                f"Native PHP {selection.branch}; "
                f"prior default {selection.before_branch or 'absent'}."
            )
        )

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        row = self.review(plan)
        if row is None:
            raise OperationRefused("The native PHP review is missing.")
        RuntimeRun.objects.create(run=run, **selection_values(row))

    def package_preconditions(self, row: RuntimeRun) -> tuple[tuple[str, str], ...]:
        return ()

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        row = RuntimeRun.objects.filter(run=run).first()
        if row is None:
            raise OperationRefused("The native PHP selection is missing.")
        conditions: tuple[tuple[str, str], ...] = ((runtime_native.DIGEST, row.default_digest),)
        if row.identifier and row.site_digest:
            from sites import native as site_native
            from sites.convention import SitePaths

            conditions = (
                *conditions,
                (
                    site_native.site_digest(
                        SitePaths(row.identifier, row.old_branch, revision=row.old_revision)
                    ),
                    row.site_digest,
                ),
            )
        if row.source_digest:
            release = releases.RELEASES.get(run.release)
            if release is None:
                raise OperationRefused("The PHP source release is missing.")
            conditions = (*conditions, (php_trust.revalidation(release), row.source_digest))
        try:
            if row.package_action:
                sockets = tuple(
                    plan.driver_pools.filter(default=False).values_list("socket", flat=True)
                )
                payload = apply.package_payload(
                    run,
                    plan,
                    preconditions=(*conditions, *self.package_preconditions(row)),
                    sockets=sockets,
                    preserve_default=row.before_branch,
                )
                return payload if row.before_branch else "; ".join(native.staged(payload))
            return runtime_native.change(
                run.unit_name,
                run.boot_id,
                run.admission_deadline_centiseconds,
                digest=row.default_digest,
                branch=row.branch,
                preconditions=conditions[1:],
            )
        except ValueError:
            raise OperationRefused("The PHP selection differs from its review.") from None

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        return None

    def execution(self, evidence: native.UnitEvidence) -> Execution:
        if (
            evidence.terminal
            and evidence.exec_main_code == native.CLD_EXITED
            and evidence.exec_main_status == 40
        ):
            return Execution.PARTIAL
        return evidence.execution

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        row = RuntimeRun.objects.filter(run=run).first()
        if row is None:
            return Verification.UNAVAILABLE
        if row.package_action and apply.verify_profile(shell, run) != Verification.PASSED:
            return Verification.FAILED
        observed = runtime_services.observe_php_runtime(shell)
        if observed.failure:
            return Verification.UNAVAILABLE
        if row.package_action == Action.PHP_LIBRARIES and not row.before_branch:
            return Verification.PASSED if observed.default is None else Verification.FAILED
        if observed.default is None:
            return Verification.UNAVAILABLE
        wanted = row.before_branch if row.package_action and row.before_branch else row.branch
        return Verification.PASSED if observed.default.branch == wanted else Verification.FAILED

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return (
            "The native PHP change did not finish. "
            "Inspect update-alternatives --query php and the retained unit. "
            "No operation is replayed."
        )

    def verification_failure(self, run: ApplyRun) -> str:
        return (
            "The selected native PHP default could not be verified. "
            "Refresh native state before another change."
        )

    def audit(self, run: ApplyRun) -> list[str]:
        row = RuntimeRun.objects.filter(run=run).first()
        return (
            []
            if row is None
            else [f"Requested PHP {row.branch}; previous default {row.before_branch or 'absent'}."]
        )


def installation_draft(
    shell: RemoteShell, draft: RuntimeDraft, package_action: Action
) -> RuntimeDraft:
    if package_action == Action.PHP and draft.php_supply == "sury":
        libraries = installation_draft(
            shell,
            replace(draft, refusals=list(draft.refusals), evidence=list(draft.evidence)),
            Action.PHP_LIBRARIES,
        )
        if not libraries.eligible or not any(
            kind == PlanEffect.Kind.NO_CHANGES for kind, _ in libraries.effects
        ):
            return libraries
    reviewed: Draft
    if package_action in profiles.BRANCH_ACTIONS:
        from databases import drivers

        reviewed = drivers.prepare(
            shell, package_action, php_version=draft.branch, php_supply=draft.php_supply
        )
        draft.driver_pools = reviewed.pools
    else:
        version = draft.branch if package_action == Action.PHP else None
        supply = draft.php_supply if package_action == Action.PHP else "ubuntu"
        evidence = inspection.inspect(shell, package_action, version=version, supply=supply)
        reviewed = review(package_action, evidence, version=version, supply=supply)
    draft.refusals.extend(reviewed.refusals)
    draft.roots = reviewed.roots
    draft.transitions = reviewed.transitions
    draft.effects = reviewed.effects
    draft.postconditions = reviewed.postconditions
    context = [
        item
        for item in draft.evidence
        if item.kind in {PlanEvidence.Kind.SITE_REVALIDATION, PlanEvidence.Kind.WORDPRESS_STATE}
    ]
    draft.evidence = [*reviewed.evidence, *context]
    draft.php_source_admitted = reviewed.php_source_admitted
    draft.php_version, draft.php_supply = reviewed.php_version, reviewed.php_supply
    draft.package_action = package_action
    return draft


HANDLER = DefaultHandler()


def _validate_source(draft: RuntimeDraft, shell: RemoteShell) -> None:
    if draft.release is None or draft.platform is None:
        return
    if not php_supply.supported(draft.branch, datetime.now(UTC).date()) or not php_supply.qualified(
        draft.release, draft.platform.architecture, draft.branch, draft.php_supply
    ):
        draft.refuse(
            PlanRefusal.Reason.UNSUPPORTED_VERSION,
            "This PHP branch and supply are not qualified.",
        )
    if draft.php_supply == "sury":
        result = shell.run(php_trust.revalidation(draft.release))
        if result.exit_status or result.truncated:
            draft.refuse(PlanRefusal.Reason.INCOMPLETE, "The PHP source cannot be revalidated.")
        else:
            try:
                draft.source_digest = native.parse_digest(result.stdout)
            except native.Unreadable:
                draft.refuse(
                    PlanRefusal.Reason.INCOMPLETE, "The PHP source fingerprint is unreadable."
                )


_SELECTION_FIELDS = (
    "branch",
    "before_branch",
    "before_mode",
    "default_digest",
    "source_digest",
    "package_action",
    "identifier",
    "old_branch",
    "old_revision",
    "site_digest",
    "old_site",
    "new_site",
    "old_pool",
    "new_pool",
    "names",
    "token",
    "body_sha256",
    "database_engine",
    "database_digest",
)


def selection_values(row: RuntimeDraft | RuntimeSelection) -> dict[str, object]:
    return {name: getattr(row, name) for name in _SELECTION_FIELDS}
