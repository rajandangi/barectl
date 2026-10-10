"""Explicit browser recovery.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

import re
from dataclasses import dataclass

from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.actions import Authority, Completion
from bootstrap.evidence import Platform
from bootstrap.models import (
    ADMISSION_CENTISECONDS,
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from bootstrap.native import Limits, UnitEvidence
from bootstrap.releases import Release
from bootstrap.review import Draft
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import native as site_native
from sites.names import valid_identifier
from tls import readiness

from . import access_reset_native as native
from . import (
    convention,
    execution,
    first_access,
    inputs,
    inspection,
    inspection_apply,
    inspection_native,
    setup_native,
)
from .access_reset_models import (
    AccessResetRequest,
    AccessReview,
    PlanWordpressAccess,
    RunWordpressAccess,
)
from .access_reset_services import PERMISSIONS
from .first_access_models import FirstAccessDelivery
from .inspection_models import InspectionReview, Operation
from .setup_native import PHAR, SHA256, VERSION

VIEW = ("servers.view_server", "wordpress.view_wordpressplan")
AUTHORITY = Authority(
    view=(*VIEW, "wordpress.manage_wordpress_credentials"),
    prepare=PERMISSIONS,
    apply=(*VIEW, "wordpress.manage_wordpress_credentials"),
)
INCOMPLETE = "The exact administrator reset review is incomplete; nothing was submitted."


class AccessDraft(inspection.InspectionDraft):
    def __init__(
        self,
        identifier: str,
        token: str,
        operation: str,
        platform: Platform | None = None,
        release: Release | None = None,
    ) -> None:
        super().__init__(
            identifier,
            token,
            operation,
            platform,
            release,
            action=Action.WORDPRESS_ACCESS,
            description=f"Explicitly reset administrator access on {identifier}.",
        )
        self.account: native.Account | None = None
        self.request: AccessResetRequest | None = None


def _extensions(draft: inspection.InspectionDraft, state: inspection_native.State) -> None:
    draft.inventory = inspection_native.inventory(state)
    if not draft.qualified:
        draft.refuse(
            PlanRefusal.Reason.UNSUPPORTED_VERSION,
            "Administrator recovery requires the exact qualified WordPress core.",
        )
    if state.dropins or state.mufiles:
        draft.refuse(
            PlanRefusal.Reason.UNSUPPORTED_LAYOUT,
            (
                "Administrator recovery refuses must-use plugins and drop-ins whose "
                "password hooks are unqualified."
            ),
        )
    if len(state.entries) > inspection_native.MAX_LISTED:
        draft.refuse(
            PlanRefusal.Reason.UNSUPPORTED_LAYOUT,
            "The application's extension inventory exceeds the bounded reset review.",
        )


def _account(draft: AccessDraft, shell: RemoteShell, request: AccessResetRequest) -> None:
    argv = native.account_argv(request.identifier, request.admin_login)
    first, second = readiness.root_read(draft, shell, argv), readiness.root_read(draft, shell, argv)
    if first is None or second is None or first != second:
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE,
            "The exact administrator identity could not be read twice consistently.",
        )
        return
    try:
        draft.account = native.parse_account(first, request.admin_login)
    except ValueError as problem:
        draft.refuse(PlanRefusal.Reason.UNSUPPORTED_LAYOUT, str(problem))


def _row_fields(draft: AccessDraft) -> dict[str, object]:
    request, account = draft.request, draft.account
    if request is None or account is None:
        raise ValueError(INCOMPLETE)
    evidence = inspection.evidence_of({item.kind: item.fingerprint for item in draft.evidence})
    if evidence is None:
        raise ValueError(INCOMPLETE)
    return {
        **inspection.inspection_fields(draft),
        "site_digest": evidence.site,
        "wpcli_digest": evidence.wpcli,
        "state_digest": evidence.state,
        "account_id": account.account_id,
        "admin_login": account.login,
        "admin_email": account.email,
        "first_name": account.first_name,
        "account_digest": account.digest,
        "password_digest": account.password_digest,
        "first_access_spki": request.first_access_spki,
        "first_access_expires_at": request.first_access_expires_at,
    }


def _prepare(preparation: PlanPreparation, shell: RemoteShell) -> AccessDraft:
    request = AccessResetRequest.objects.filter(preparation=preparation).first()
    if (
        request is None
        or not valid_identifier(request.identifier)
        or not inputs.LOGIN.fullmatch(request.admin_login)
    ):
        raise OperationRefused(INCOMPLETE)
    try:
        first_access.validate_key(request.first_access_spki)
    except ValueError:
        raise OperationRefused(INCOMPLETE) from None
    if request.first_access_expires_at <= timezone.now():
        raise OperationRefused("The requesting browser key expired before review.")
    draft = inspection.observe(
        shell, request.identifier, Operation.INSPECT, AccessDraft, _extensions
    )
    if not isinstance(draft, AccessDraft):
        raise TypeError(INCOMPLETE)
    draft.request = request
    if draft.ready:
        _account(draft, shell, request)
    if draft.ready and draft.account is not None:
        _payload_review(draft)
        draft.effects += [
            (
                PlanEffect.Kind.APP_EXECUTION,
                (
                    f"Runs authenticated WP-CLI {VERSION} as "
                    f"{draft.paths.user if draft.paths else ''}, "
                    "with ordinary plugins/themes skipped "
                    "and no application-supplied CLI configuration."
                ),
            ),
            (
                PlanEffect.Kind.APP_STATE,
                (
                    f"Changes only the reviewed administrator {request.admin_login}'s password; "
                    "WP-CLI --skip-email needs no outbound mail. "
                    "Existing login, email, first name, "
                    "roles, site content and routing are preserved."
                ),
            ),
            (
                PlanEffect.Kind.APP_RESULT,
                (
                    "Delivers one RSA-OAEP encrypted password only to the original "
                    "requesting browser, once and before expiry. No plaintext password "
                    "enters request records, command arguments or logs. Failure never "
                    "automatically repeats the reset."
                ),
            ),
        ]
    return draft


def _evidence(plan: ConfigurationPlan) -> inspection_native.Evidence:
    found = inspection.evidence_of(dict(plan.evidence.values_list("kind", "fingerprint")))
    if found is None:
        raise OperationRefused(INCOMPLETE)
    return found


def _payload_review(draft: AccessDraft) -> None:
    platform = draft.platform
    evidence = inspection.evidence_of({item.kind: item.fingerprint for item in draft.evidence})
    if platform is None or platform.uptime_centiseconds is None or evidence is None:
        draft.refuse(PlanRefusal.Reason.INCOMPLETE, INCOMPLETE)
        return
    row = PlanWordpressAccess(**_row_fields(draft))
    body = native.body(row, evidence)
    payload = execution.payload(
        bootstrap_native.new_unit_name(),
        platform.boot_id,
        platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
        body,
    )
    draft.body_sha256 = inspection.digest(body)
    draft.payload_bytes = len(payload.encode())
    if draft.payload_bytes > bootstrap_native.MAX_PAYLOAD:
        draft.refuse(
            PlanRefusal.Reason.PAYLOAD_TOO_LARGE, "The reset exceeds one bounded native submission."
        )


def _fields(row: AccessReview) -> dict[str, object]:
    return {
        field.name: getattr(row, field.name)
        for model in (InspectionReview, AccessReview)
        for field in model._meta.local_fields
    }


def _pinned(row: AccessReview) -> bool:
    return (
        row.core_qualified
        and row.core_version == convention.CORE_VERSION
        and row.tool_path == PHAR
        and row.tool_sha256 == SHA256
        and row.tool_version == VERSION
        and row.core_locale == "en_US"
        and row.operation == Operation.INSPECT
        and (row.max_file_bytes, row.memory_max_bytes) == inspection_native.limits()
        and row.runtime_limit_seconds == inspection_native.RUNTIME_LIMIT_SECONDS
        and row.command_seconds == inspection_native.COMMAND_SECONDS
        and row.budget_seconds == inspection_native.BUDGET_SECONDS
    )


def _binding_reads(row: AccessReview) -> tuple[tuple[list[str], str], ...]:
    target = inspection_native.target_of(row)
    return (
        (
            site_native.script(site_native.site_digest(target.verified())),
            row.site_digest,
        ),
        (site_native.script(setup_native.wpcli_digest()), row.wpcli_digest),
    )


def _read_account(shell: RemoteShell, row: AccessReview, root: bool) -> native.Account | None:
    argv = native.account_argv(row.identifier, row.admin_login)
    if not root and shell.run(bootstrap_native.authorization(argv)).exit_status:
        return None
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status or result.truncated:
        return None
    try:
        return native.parse_account(result.stdout, row.admin_login)
    except ValueError:
        return None


def _verify_bindings(shell: RemoteShell, row: AccessReview, root: bool) -> Verification | None:
    for command, expected in _binding_reads(row):
        if not root and shell.run(bootstrap_native.authorization(command)).exit_status:
            return Verification.UNAVAILABLE
        answer = shell.run(bootstrap_native.privileged(command, root=root))
        if answer.exit_status or answer.truncated:
            return Verification.UNAVAILABLE
        if not answer.stdout.split() or answer.stdout.split()[0] != expected:
            return Verification.FAILED
    return None


def _account_outcome(
    shell: RemoteShell, run: ApplyRun, row: AccessReview, root: bool
) -> tuple[Verification | None, str]:
    invocation = (
        ApplyRun.objects.filter(pk=run.pk).values_list("invocation_id", flat=True).first() or ""
    )
    if not execution.INVOCATION.fullmatch(invocation):
        return Verification.UNAVAILABLE, ""
    journal = shell.run(
        execution.retrieval_command(
            execution.retrieval_argv(run.unit_name, row.identifier), invocation, root=root
        )
    )
    if journal.exit_status or journal.truncated:
        return Verification.UNAVAILABLE, ""
    try:
        retrieved = execution.parse_retrieval(
            journal.stdout, unit=run.unit_name, invocation=invocation
        )
    except execution.Unreadable:
        return Verification.UNAVAILABLE, ""
    if retrieved.residue:
        return Verification.FAILED, ""
    record = retrieved.record or ""
    matched = re.fullmatch(r'\{"account_digest":"([0-9a-f]{64})"\}', record)
    if matched is None:
        return Verification.UNAVAILABLE, ""
    return None, matched[1]


@dataclass(frozen=True)
class AccessHandler:
    actions: frozenset[str] = frozenset({Action.WORDPRESS_ACCESS})
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "wordpress/_access_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return _prepare(preparation, shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, AccessDraft) and draft.ready and draft.account is not None:
            PlanWordpressAccess.objects.create(plan=plan, **_row_fields(draft))

    def prefetch(self) -> tuple[str, ...]:
        return ("wordpress_access",)

    def review(self, plan: ConfigurationPlan) -> PlanWordpressAccess | None:
        return PlanWordpressAccess.objects.filter(plan=plan).first()

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        row = self.review(plan)
        return (
            ""
            if row is None
            else f"Reset administrator {row.admin_login} on {row.url}; "
            "encrypted delivery to the original browser."
        )

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        row = self.review(plan)
        if row is None:
            raise OperationRefused(INCOMPLETE)
        RunWordpressAccess.objects.create(run=run, **_fields(row))
        FirstAccessDelivery.objects.create(
            run=run,
            requested_by_id=plan.preparation.requested_by_id,
            key_sha256=first_access.key_digest(row.first_access_spki),
            expires_at=row.first_access_expires_at,
            unavailable=True,
        )

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        row = self.review(plan)
        if row is None or not _pinned(row):
            raise OperationRefused(INCOMPLETE)
        try:
            body = native.body(row, _evidence(plan))
        except ValueError:
            raise OperationRefused(INCOMPLETE) from None
        if inspection.digest(body) != row.body_sha256:
            raise OperationRefused(INCOMPLETE)
        return execution.payload(
            run.unit_name, run.boot_id, run.admission_deadline_centiseconds, body
        )

    def limits(self, run: ApplyRun) -> Limits:
        row = RunWordpressAccess.objects.filter(run=run).first()
        if row is None or not _pinned(row):
            raise OperationRefused(INCOMPLETE)
        return Limits(row.max_file_bytes, row.memory_max_bytes)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        row = RunWordpressAccess.objects.filter(run=run).first()
        if row is None:
            raise OperationRefused(INCOMPLETE)
        commands: tuple[list[str], ...] = (
            execution.retrieval_argv(run.unit_name, row.identifier),
            native.account_argv(row.identifier, row.admin_login),
            inspection_native.state_argv(row.identifier),
        )
        commands += tuple(argv for argv, _ in _binding_reads(row))
        if not root and any(
            shell.run(bootstrap_native.authorization(argv)).exit_status for argv in commands
        ):
            raise OperationRefused(
                "The SSH account cannot read the exact account, application state and "
                "encrypted run journal for verification."
            )

    def execution(self, evidence: UnitEvidence) -> Execution:
        return inspection_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        row = RunWordpressAccess.objects.filter(run=run).first()
        root = bootstrap_native.is_root(shell)
        if row is None or root is None:
            return Verification.UNAVAILABLE
        account = _read_account(shell, row, root)
        argv = inspection_native.state_argv(row.identifier)
        if not root and shell.run(bootstrap_native.authorization(argv)).exit_status:
            return Verification.UNAVAILABLE
        state = shell.run(bootstrap_native.privileged(argv, root=root))

        if account is None or state.exit_status or state.truncated:
            return Verification.UNAVAILABLE
        if (
            account.identity() != (row.account_id, row.admin_login, row.admin_email, row.first_name)
            or account.password_digest == row.password_digest
            or inspection.digest(state.stdout) != row.state_digest
        ):
            return Verification.FAILED
        verified = _verify_bindings(shell, row, root)
        if verified is not None:
            return verified
        outcome, original = _account_outcome(shell, run, row, root)
        if outcome is not None:
            return outcome
        if account.digest != original:
            return Verification.FAILED
        first_access.capture(
            shell, run, row.identifier, row.first_access_spki, row.first_access_expires_at
        )
        return Verification.PASSED

    def failure(self, run: ApplyRun, outcome: Execution, exit_status: int | None) -> str:
        if outcome == Execution.SUCCEEDED:
            return ""
        if outcome in {
            Execution.LOCK_CONFLICT,
            Execution.UNSAFE_LOCK,
            Execution.BOOT_CHANGED,
            Execution.EXPIRED,
            Execution.OTHER_RUN_ACTIVE,
            Execution.RENEWAL_ACTIVE,
            Execution.CAPACITY,
        }:
            return inspection_apply.failure(run, outcome, exit_status)
        if outcome in {Execution.DRIFT, Execution.INSPECTION_REFUSED}:
            return (
                "The reviewed account or application changed, or native admission "
                "refused; no password command ran. Prepare a new explicit request."
            )
        return (
            "The original reset did not complete reliably; the password may have "
            "changed. Inspect that native run and account. Barectl never repeats it "
            "automatically."
        )

    def verification_failure(self, run: ApplyRun) -> str:
        return (
            "The original reset did not verify its exact account and unchanged "
            "application state; encrypted delivery is unavailable. Inspect the "
            "original run before any new explicit reset."
        )

    def audit(self, run: ApplyRun) -> list[str]:
        return []

    def completion(self, run: ApplyRun) -> Completion | None:
        row = RunWordpressAccess.objects.filter(run=run).first()
        if row is None or run.verification != Verification.PASSED:
            return None
        return Completion(
            url=f"{row.url}/wp-admin/",
            label="Open WordPress dashboard",
            observed=False,
            note=(
                "Administrator access was explicitly reset; open encrypted delivery in "
                "the requesting browser."
            ),
            permission=AUTHORITY.apply,
            heading="Open first access in the requesting browser",
        )


ACCESS_HANDLER = AccessHandler()
