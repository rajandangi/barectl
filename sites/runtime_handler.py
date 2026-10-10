"""An existing site's runtime is admitted from native pools, catalogs and package supply."""

import hashlib
import secrets
import shlex
from dataclasses import dataclass, replace
from typing import override

from bootstrap import inspection as package_inspection
from bootstrap import native as bootstrap_native
from bootstrap import profiles
from bootstrap import review as package_review
from bootstrap.actions import BOOTSTRAP, Authority
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
    Privilege,
    Verification,
)
from bootstrap.runtime_handler import (
    DefaultHandler,
    RuntimeDraft,
    _validate_source,
    installation_draft,
)
from bootstrap.runtime_models import RuntimeRequest, RuntimeRun
from bootstrap.runtime_services import PhpRuntimeObservation, observe_php_runtime
from databases import inspection as catalog_inspection
from databases.handler import AUTHORITY as DATABASE_AUTHORITY
from discovery.models import DatabaseEngine, ObservationOutcome
from discovery.observations import databases as catalog_native
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from wordpress import qualification

from . import admission, inspection, native, runtime_native
from .convention import RecognizedSite, SitePaths, render_pool, render_site
from .handler import AUTHORITY

SWITCH_AUTHORITY = Authority(
    view=tuple(dict.fromkeys((*AUTHORITY.view, *DATABASE_AUTHORITY.view, *BOOTSTRAP.view))),
    prepare=tuple(
        dict.fromkeys((*AUTHORITY.prepare, *DATABASE_AUTHORITY.prepare, *BOOTSTRAP.prepare))
    ),
    apply=tuple(dict.fromkeys((*AUTHORITY.apply, *DATABASE_AUTHORITY.apply, *BOOTSTRAP.apply))),
)


@dataclass(frozen=True)
class SwitchHandler(DefaultHandler):
    actions: frozenset[str] = frozenset({Action.SITE_PHP_SWITCH})
    authority: Authority = SWITCH_AUTHORITY

    @override
    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> RuntimeDraft:
        request = RuntimeRequest.objects.filter(preparation=preparation).first()
        if request is None or request.branch not in ("8.3", "8.4", "8.5") or not request.identifier:
            raise OperationRefused("The site PHP request is missing or invalid.")
        token = secrets.token_hex(16)
        evidence = inspection.inspect(shell, request.identifier, token)
        draft = RuntimeDraft(
            Action.SITE_PHP_SWITCH,
            f"Switch site {request.identifier} to PHP {request.branch}.",
            evidence.platform,
            evidence.release,
            branch=request.branch,
            identifier=request.identifier,
            token=token,
        )
        site = admission.complete(draft, evidence, request.identifier, token)
        paths = evidence.paths
        if site is None or paths is None or not draft.eligible:
            return draft
        observed = _runtime(draft, shell)
        if observed is None:
            return draft
        draft.old_branch, draft.old_revision, draft.site_digest = (
            paths.php,
            paths.revision,
            evidence.digest,
        )
        draft.old_site, draft.old_pool = (
            evidence.contents.get(paths.source, ""),
            evidence.contents.get(paths.pool, ""),
        )
        draft.names = "\n".join(site.names)
        _validate_source(draft, shell)
        _application(draft, shell, site)
        if draft.refusals:
            return draft
        if draft.branch == draft.old_branch:
            draft.effects = [(PlanEffect.Kind.NO_CHANGES, "The site already uses this PHP branch.")]
            return draft
        _binding(draft, shell)
        if draft.refusals:
            return draft
        if draft.branch not in observed.installed:
            return installation_draft(shell, draft, Action.PHP)
        missing = _missing_capability(shell, draft)
        if missing is not None:
            return _install_capability(shell, draft, missing)
        return _replacement(draft, shell, evidence, site)

    @override
    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        row = RuntimeRun.objects.filter(run=run).first()
        if row is None:
            raise OperationRefused("The site runtime review is missing.")
        if row.package_action:
            return super().payload(run, plan)
        try:
            return runtime_native.payload(
                run.unit_name,
                run.boot_id,
                run.admission_deadline_centiseconds,
                _change(row),
                default_digest=row.default_digest,
                site_digest=row.site_digest,
                body_sha256=row.body_sha256,
                binding=(*_catalog_precondition(row), _target_precondition(run, plan)),
                wordpress_digest=_wordpress_digest(plan),
            )
        except ValueError:
            raise OperationRefused("The site runtime payload differs from its review.") from None

    @override
    def package_preconditions(self, row: RuntimeRun) -> tuple[tuple[str, str], ...]:
        plan = row.run.plan
        if plan is None:
            raise OperationRefused("The site runtime review is missing.")
        return (
            *_catalog_precondition(row),
            *_wordpress_precondition(row.identifier, row.old_site, plan),
        )

    @override
    def execution(self, evidence: bootstrap_native.UnitEvidence) -> Execution:
        if (
            evidence.terminal
            and evidence.exec_main_code == bootstrap_native.CLD_EXITED
            and evidence.exec_main_status in (40, 41)
        ):
            return Execution.PARTIAL
        return evidence.execution

    @override
    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        row = RuntimeRun.objects.filter(run=run).first()
        if row is None:
            return Verification.UNAVAILABLE
        if row.package_action:
            return super().verify(shell, run)
        observed = observe_php_runtime(shell)
        if observed.failure or observed.default is None:
            return Verification.UNAVAILABLE
        evidence = inspection.inspect(shell, row.identifier, row.token)
        draft = RuntimeDraft(
            Action.SITE_PHP_SWITCH,
            "Verify selected site runtime.",
            evidence.platform,
            evidence.release,
            identifier=row.identifier,
        )
        site = admission.complete(draft, evidence, row.identifier, row.token)
        if site is None or evidence.paths is None or not draft.eligible:
            return Verification.FAILED
        if site.application.wordpress:
            _passive_wordpress(draft, shell)
            if draft.refusals or run.plan is None:
                return Verification.FAILED
            before = _wordpress_digest(run.plan)
            after = next(
                (
                    item.fingerprint
                    for item in draft.evidence
                    if item.kind == PlanEvidence.Kind.WORDPRESS_STATE
                ),
                "",
            )
            if not before or after != before:
                return Verification.FAILED
        return (
            Verification.PASSED
            if (
                evidence.paths.php == row.branch
                and evidence.contents.get(evidence.paths.source) == row.new_site
                and evidence.contents.get(evidence.paths.pool) == row.new_pool
                and observed.default.branch == row.before_branch
            )
            else Verification.FAILED
        )


def _application(draft: RuntimeDraft, shell: RemoteShell, site: RecognizedSite) -> None:
    if site.application.wordpress:
        _wordpress(draft, draft.old_branch)
        if not draft.refusals:
            _passive_wordpress(draft, shell)


def _runtime(draft: RuntimeDraft, shell: RemoteShell) -> PhpRuntimeObservation | None:
    observed = observe_php_runtime(shell)
    if observed.failure or observed.default is None:
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE,
            observed.failure or "The native server default is missing.",
        )
        return None
    draft.php_version, draft.php_supply = draft.branch, observed.supply or "ubuntu"
    draft.before_branch, draft.before_mode = observed.default.branch, observed.default.mode
    draft.default_digest = observed.fingerprint
    return observed


def _install_capability(shell: RemoteShell, draft: RuntimeDraft, action: Action) -> RuntimeDraft:
    if action == Action.PHP_WORDPRESS:
        libraries = installation_draft(
            shell,
            replace(draft, refusals=list(draft.refusals), evidence=list(draft.evidence)),
            Action.WORDPRESS_LIBRARIES,
        )
        if not libraries.eligible or not any(
            kind == PlanEffect.Kind.NO_CHANGES for kind, _ in libraries.effects
        ):
            return libraries
    return installation_draft(shell, draft, action)


def _wordpress(draft: RuntimeDraft, old_branch: str) -> None:
    release, platform = draft.release, draft.platform
    if (
        release is None
        or platform is None
        or not qualification.qualified(
            release.version, platform.architecture, draft.branch, draft.php_supply
        )
        or not qualification.qualified(
            release.version, platform.architecture, old_branch, draft.php_supply
        )
    ):
        draft.refuse(
            PlanRefusal.Reason.UNSUPPORTED_VERSION,
            "The requested WordPress PHP selection has not completed WordPress qualification.",
        )
    elif old_branch == draft.branch:
        draft.effects = [
            (
                PlanEffect.Kind.NO_CHANGES,
                "The WordPress site already uses the qualified PHP branch.",
            )
        ]


def _passive_wordpress(draft: RuntimeDraft, shell: RemoteShell) -> None:
    from wordpress import inspection as wordpress_inspection
    from wordpress.inspection_models import Operation

    inspected = wordpress_inspection.observe(
        shell,
        draft.identifier,
        Operation.INSPECT,
        wordpress_inspection.InspectionDraft,
        wordpress_inspection._extensions,
    )
    draft.refusals.extend(inspected.refusals)
    if not inspected.ready or not inspected.qualified:
        draft.refuse(
            PlanRefusal.Reason.UNSUPPORTED_VERSION,
            "Only the qualified installed WordPress release can switch PHP runtimes.",
        )
        return
    draft.evidence.extend(
        item for item in inspected.evidence if item.kind == PlanEvidence.Kind.WORDPRESS_STATE
    )


def _wordpress_digest(plan: ConfigurationPlan) -> str:
    return (
        plan.evidence.filter(kind=PlanEvidence.Kind.WORDPRESS_STATE)
        .values_list("fingerprint", flat=True)
        .first()
        or ""
    )


def _wordpress_precondition(
    identifier: str, site_text: str, plan: ConfigurationPlan
) -> tuple[tuple[str, str], ...]:
    from wordpress import inspection_native

    from .convention import recognize_site

    site = recognize_site(identifier, site_text)
    if site is None or not site.application.wordpress:
        return ()
    fingerprint = _wordpress_digest(plan)
    if not fingerprint:
        raise OperationRefused("The passive WordPress state fingerprint is missing.")
    command = shlex.join(
        native.script(
            "; ".join(bootstrap_native.staged(inspection_native.state_script(identifier)))
        )
    )
    return ((command + " | sha256sum", fingerprint),)


def _binding(draft: RuntimeDraft, shell: RemoteShell) -> None:
    catalog = catalog_inspection.prepare(shell)
    draft.refusals.extend(catalog.refusals)
    observed = next(
        (
            database
            for identifier, database in catalog.observations
            if identifier == draft.identifier
        ),
        None,
    )
    if observed is None or observed.outcome not in (
        ObservationOutcome.ABSENT,
        ObservationOutcome.OBSERVED,
    ):
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE, "The site's native database binding cannot be read."
        )
        return
    if observed.outcome == ObservationOutcome.ABSENT:
        return
    if not observed.conforms or observed.engine is None:
        draft.refuse(
            PlanRefusal.Reason.NOT_FOLLOWING,
            "The site's database binding does not follow the native convention.",
        )
        return
    draft.database_engine = observed.engine
    command = _catalog_command(draft.identifier, draft.database_engine)
    root = draft.platform is not None and draft.platform.privilege == Privilege.ROOT
    result = shell.run(bootstrap_native.privileged(native.script(command), root=root))
    if result.exit_status or result.truncated:
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE, "The native binding fingerprint is unavailable."
        )
    else:
        draft.database_digest = bootstrap_native.parse_digest(result.stdout)


def _catalog_command(identifier: str, engine: str) -> str:
    name = "s" + SitePaths(identifier, "8.3").identifier
    if engine == DatabaseEngine.MARIADB:
        command = catalog_native.mariadb_command((name,))
    elif engine == DatabaseEngine.POSTGRESQL:
        command = (
            catalog_native.postgresql_command((name,))
            + "; "
            + catalog_native.postgresql_schema_command(name)
        )
    else:
        raise ValueError("Unsupported native database binding.")
    return "{ " + command + "; } | sha256sum"


def _catalog_precondition(row: RuntimeRun) -> tuple[tuple[str, str], ...]:
    if not row.database_engine:
        return ()
    return ((_catalog_command(row.identifier, row.database_engine), row.database_digest),)


def _target_precondition(run: ApplyRun, plan: ConfigurationPlan) -> tuple[str, str]:
    from bootstrap import releases

    release = releases.RELEASES.get(run.release)
    digest = (
        plan.evidence.filter(kind=PlanEvidence.Kind.PACKAGE_REVALIDATION)
        .values_list("fingerprint", flat=True)
        .first()
    )
    if release is None or not digest:
        raise OperationRefused("The target PHP-FPM admission fingerprint is missing.")
    profile = profiles.profile(release, Action.PHP, version=run.php_version, supply=run.php_supply)
    return profile.revalidation, digest


def _modules(
    shell: RemoteShell, branch: str, *, without_ini: bool = False
) -> frozenset[str] | None:
    options = "-n -m" if without_ini else "-m"
    result = shell.run(f"/usr/sbin/php-fpm{branch} {options}")
    if result.exit_status or result.truncated:
        return None
    return frozenset(
        line.strip().lower()
        for line in result.stdout.splitlines()
        if line.strip() and not line.startswith("[")
    )


def _missing_capability(shell: RemoteShell, draft: RuntimeDraft) -> Action | None:
    old, selected = _modules(shell, draft.old_branch), _modules(shell, draft.branch)
    old_builtin = _modules(shell, draft.old_branch, without_ini=True)
    selected_builtin = _modules(shell, draft.branch, without_ini=True)
    if (
        old is None
        or selected is None
        or old_builtin is None
        or selected_builtin is None
        or "core" not in old_builtin
        or "core" not in selected_builtin
        or not old_builtin <= old
        or not selected_builtin <= selected
    ):
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE, "The old and selected FPM capabilities are unreadable."
        )
        return None
    missing = (old - old_builtin) - selected
    if missing & {"mysqli", "pdo_mysql"}:
        return Action.PHP_MYSQL
    if missing & {"pgsql", "pdo_pgsql"}:
        return Action.PHP_PGSQL
    if missing & {
        "curl",
        "gd",
        "intl",
        "mbstring",
        "zip",
        "dom",
        "xml",
        "xmlreader",
        "xmlwriter",
        "simplexml",
    }:
        return Action.PHP_WORDPRESS
    if missing:
        draft.refuse(
            PlanRefusal.Reason.UNSUPPORTED_VERSION,
            "The selected runtime cannot preserve the current FPM modules.",
        )
    return None


def _change(row: RuntimeDraft | RuntimeRun) -> runtime_native.Switch:
    return runtime_native.Switch(
        row.identifier,
        row.old_branch,
        row.branch,
        row.old_revision,
        row.old_site,
        row.new_site,
        row.old_pool,
        row.new_pool,
        row.token,
        row.database_engine,
    )


HANDLER = SwitchHandler()


def _replacement(
    draft: RuntimeDraft, shell: RemoteShell, evidence: inspection.SiteEvidence, site: RecognizedSite
) -> RuntimeDraft:
    target = (
        inspection.inspect_trees(
            shell, evidence.platform, evidence.release, php_version=draft.branch
        )
        if evidence.platform is not None and evidence.release is not None
        else None
    )
    if target is None or admission.recognize_trees(target) is None or target.gaps:
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE,
            "The target PHP-FPM trees cannot be reconstructed safely.",
        )
        return draft
    _target_unit(draft, shell)
    if draft.refusals:
        return draft
    new = SitePaths(draft.identifier, draft.branch, revision=4)
    if new.pool in target.contents:
        draft.refuse(
            PlanRefusal.Reason.CONFLICT, "The target branch already holds a pool for this site."
        )
        return draft
    draft.new_pool = render_pool(draft.identifier, php_version=draft.branch)
    draft.new_site = render_site(
        draft.identifier,
        site.names,
        ipv6=site.ipv6,
        stage=site.stage,
        php_version=draft.branch,
        application=site.application,
        canonical=site.canonical,
    )
    draft.effects = [
        (
            PlanEffect.Kind.SITE_FILES,
            (
                "Replace only this site's pool and Nginx PHP reference; "
                "keep its identity, content and database."
            ),
        ),
        (
            PlanEffect.Kind.SERVICE_RELOAD,
            (
                "Reload the old and selected FPM branches and Nginx, "
                "verifying this site's runtime identity."
            ),
        ),
    ]
    digest = next(
        (
            item.fingerprint
            for item in draft.evidence
            if item.kind == PlanEvidence.Kind.PACKAGE_REVALIDATION
        ),
        "",
    )
    if not digest or draft.release is None:
        draft.refuse(PlanRefusal.Reason.INCOMPLETE, "The target FPM fingerprint is missing.")
        return draft
    profile = profiles.profile(
        draft.release, Action.PHP, version=draft.branch, supply=draft.php_supply
    )
    binding: tuple[tuple[str, str], ...] = ((profile.revalidation, digest),)
    if draft.database_engine:
        binding = (
            (_catalog_command(draft.identifier, draft.database_engine), draft.database_digest),
            *binding,
        )
    draft.body_sha256 = hashlib.sha256(
        runtime_native.body(
            _change(draft),
            default_digest=draft.default_digest,
            site_digest=draft.site_digest,
            binding=binding,
            wordpress_digest=next(
                (
                    item.fingerprint
                    for item in draft.evidence
                    if item.kind == PlanEvidence.Kind.WORDPRESS_STATE
                ),
                "",
            ),
        ).encode()
    ).hexdigest()
    return draft


def _target_unit(draft: RuntimeDraft, shell: RemoteShell) -> None:
    evidence = package_inspection.inspect(
        shell, Action.PHP, version=draft.branch, supply=draft.php_supply
    )
    web = evidence.web
    if draft.release is None or web is None or evidence.packages is None or evidence.gaps:
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE, "The selected native FPM service is unreadable."
        )
        return
    profile = profiles.profile(
        draft.release, Action.PHP, version=draft.branch, supply=draft.php_supply
    )
    installed = {state.name for state in evidence.packages.states if state.installed}
    effects = package_review._check_units(draft, profile, web.units, installed)
    package_review._check_configuration(draft, profile, web, installed=True)
    package_review._revalidation(draft, evidence)
    if effects:
        draft.refuse(
            PlanRefusal.Reason.SERVICE_UNIT,
            "The selected FPM branch must already be enabled and running.",
        )
