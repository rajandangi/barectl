"""Node runtime plans through the existing worker (docs/node-runtimes-native-design.md)."""

from dataclasses import dataclass
from typing import override

from bootstrap import inspection, releases
from bootstrap import native as execution
from bootstrap.actions import BOOTSTRAP, Authority, PermissionStage
from bootstrap.models import (
    ADMISSION_CENTISECONDS,
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
from bootstrap.native import UnitEvidence
from bootstrap.review import Draft, EvidenceDraft, check_platform
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites.names import valid_identifier
from sites.native import script

from . import catalog, native, permissions, runtime
from .models import PlanNodeRuntime, RunNodeRuntime, RuntimeRequest


@dataclass
class RuntimeDraft(Draft):
    version: str = ""
    identifier: str = ""
    digest: str = ""
    before: runtime.Inventory | None = None

    @property
    @override
    def revision(self) -> int:
        return 1


def _read(shell: RemoteShell, argv: list[str], *, root: bool) -> str:
    if not root and shell.run(execution.authorization(argv)).exit_status:
        raise runtime.Unreadable(
            "Noninteractive privilege does not authorize this fixed Node read."
        )
    result = shell.run(execution.privileged(argv, root=root))
    if result.exit_status or result.truncated:
        raise runtime.Unreadable("Node native evidence is incomplete or unsafe.")
    return result.stdout


def _request(preparation: PlanPreparation) -> RuntimeRequest | None:
    request = RuntimeRequest.objects.filter(preparation=preparation).first()
    if request is not None:
        permissions.admit(preparation.requested_by_id, request.identifier, "prepare")
    return request


@dataclass(frozen=True)
class RuntimeHandler:
    actions: frozenset[str] = frozenset({"node_runtime"})
    authority: Authority = BOOTSTRAP
    applicable: bool = True
    review_template: str = "node_runtimes/_review.html"

    def operation_permissions(
        self, operation_id: int, stage: PermissionStage
    ) -> tuple[str, ...] | None:
        return permissions.operation_required(operation_id, stage)

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> RuntimeDraft:
        request = _request(preparation)
        reader = inspection.Reader(shell)
        platform = inspection.read_platform(reader)
        release = releases.of(platform.os) if platform else None
        draft = RuntimeDraft(
            Action.NODE_RUNTIME, "Select an exact native Node LTS runtime.", platform, release
        )
        check_platform(draft, platform)
        for gap in reader.gaps:
            draft.refuse(PlanRefusal.Reason.INCOMPLETE, gap)
        if (
            request is None
            or request.version not in catalog.VERSIONS
            or (request.identifier and not valid_identifier(request.identifier))
        ):
            draft.refuse(
                PlanRefusal.Reason.UNSUPPORTED_VERSION,
                "Select a reviewed Node LTS release and recognized site identifier.",
            )
            return draft
        draft.version, draft.identifier = request.version, request.identifier
        if not draft.eligible or platform is None:
            return draft
        root = platform.privilege == Privilege.ROOT
        try:
            before = _read(shell, script(native.digest_text(request.identifier)), root=root)
            draft.before = runtime.inspect(shell, root=root)
            if request.identifier:
                _read(
                    shell,
                    script(native.SAFE + "; " + native.site_check(request.identifier)),
                    root=root,
                )
            _read(
                shell,
                script("test -x /usr/bin/curl && test -x /usr/bin/gpg && test -x /usr/bin/gpgv"),
                root=root,
            )
            after = _read(shell, script(native.digest_text(request.identifier)), root=root)
            if before != after:
                raise runtime.Unreadable("Node state changed during review; prepare again.")
            draft.digest = execution.parse_digest(after)
        except (runtime.Unreadable, execution.Unreadable) as error:
            draft.refuse(PlanRefusal.Reason.INCOMPLETE, str(error))
            return draft
        draft.evidence.append(
            EvidenceDraft(
                PlanEvidence.Kind.NODE_REVALIDATION,
                draft.digest,
                "Native runtime/default/site pin evidence rechecked under the mutation lock.",
            )
        )
        current = (
            draft.before.sites.get(request.identifier, "")
            if request.identifier
            else draft.before.default
        )
        if current == request.version and request.version in draft.before.installed:
            draft.effects.append(
                (
                    PlanEffect.Kind.NO_CHANGES,
                    "The exact selected Node runtime and pin are already present.",
                )
            )
        else:
            draft.effects.append(
                (
                    PlanEffect.Kind.TOOL_INSTALL,
                    (
                        f"Authenticate and install Node {request.version} on demand; "
                        f"select it for {request.identifier or 'future sites'}. "
                        "Existing site pins stay unchanged."
                    ),
                )
            )
            try:
                body = native.payload(
                    execution.new_unit_name(),
                    platform.boot_id,
                    (platform.uptime_centiseconds or 0) + ADMISSION_CENTISECONDS,
                    version=request.version,
                    architecture=platform.architecture,
                    identifier=request.identifier,
                    digest=draft.digest,
                )
            except ValueError:
                draft.refuse(
                    PlanRefusal.Reason.UNSUPPORTED_VERSION,
                    "Unsupported Node architecture or request.",
                )
                return draft
            if len(body.encode()) > execution.MAX_PAYLOAD:
                draft.refuse(
                    PlanRefusal.Reason.PAYLOAD_TOO_LARGE,
                    "The Node payload exceeds the native submission limit.",
                )
        draft.postconditions.append(
            f"Node executable: {catalog.executable(request.version)}. "
            "No application deployment or service change."
        )
        return draft

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if not isinstance(draft, RuntimeDraft) or not draft.eligible or draft.before is None:
            return
        PlanNodeRuntime.objects.create(
            plan=plan,
            version=draft.version,
            identifier=draft.identifier,
            architecture=plan.architecture,
            digest=draft.digest,
            default_before=draft.before.default,
            pin_before=draft.before.sites.get(draft.identifier, ""),
            executable=catalog.executable(draft.version),
            installs_runtime=draft.version not in draft.before.installed,
        )

    def prefetch(self) -> tuple[str, ...]:
        return ("node_runtime",)

    def review(self, plan: ConfigurationPlan) -> PlanNodeRuntime | None:
        return PlanNodeRuntime.objects.filter(plan=plan).first()

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        review = self.review(plan)
        return (
            ""
            if review is None
            else (
                f"Select Node {review.version} for {review.identifier or 'server default'}; "
                f"executable {review.executable}."
            )
        )

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        review = self.review(plan)
        if review is None:
            raise OperationRefused("The Node review is unavailable. Prepare again.")
        RunNodeRuntime.objects.create(
            run=run,
            **{f.name: getattr(review, f.name) for f in review._meta.fields if f.name != "plan"},
        )

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        review = self.review(plan)
        if review is not None:
            permissions.admit(run.requested_by_id, review.identifier, "apply")
        if (
            review is None
            or review.executable != catalog.executable(review.version)
            or plan.profile_revision != 1
        ):
            raise OperationRefused("The Node review does not match this runtime definition.")
        try:
            return native.payload(
                run.unit_name,
                run.boot_id,
                run.admission_deadline_centiseconds,
                version=review.version,
                architecture=review.architecture,
                identifier=review.identifier,
                digest=review.digest,
            )
        except ValueError:
            raise OperationRefused("The Node review is invalid; prepare again.") from None

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        review = RunNodeRuntime.objects.filter(run=run).first()
        if review is None:
            raise OperationRefused("The Node review is unavailable. Prepare again.")
        permissions.admit(run.requested_by_id, review.identifier, "apply")
        if not root and shell.run(execution.authorization(native.inventory())).exit_status:
            raise OperationRefused("Noninteractive privilege cannot verify Node after applying.")

    def execution(self, evidence: UnitEvidence) -> Execution:
        if evidence.found and evidence.terminal and evidence.exec_main_code == execution.CLD_EXITED:
            if evidence.exec_main_status in {31, 32, 33}:
                return Execution.TOOL_REFUSED
            if evidence.exec_main_status == 34:
                return Execution.PARTIAL
        return evidence.execution

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        review = RunNodeRuntime.objects.filter(run=run).first()
        root = execution.is_root(shell)
        if root is None or review is None:
            return Verification.UNAVAILABLE
        try:
            found = runtime.inspect(shell, root=root)
        except runtime.Unreadable:
            return Verification.UNAVAILABLE
        selected = found.sites.get(review.identifier, "") if review.identifier else found.default
        return (
            Verification.PASSED
            if selected == review.version and review.version in found.installed
            else Verification.FAILED
        )

    def failure(self, run: ApplyRun, outcome: Execution, exit_status: int | None) -> str:
        return (
            ""
            if outcome == Execution.SUCCEEDED
            else (
                f"Node runtime selection stopped (status {exit_status}). "
                "Inspect the retained systemd journal and native files, then prepare again; "
                "no automatic retry or rollback."
            )
        )

    def verification_failure(self, run: ApplyRun) -> str:
        return (
            "The native Node runtime or selected pin differs from its review. "
            "Inspect native state and prepare again."
        )

    def audit(self, run: ApplyRun) -> list[str]:
        review = RunNodeRuntime.objects.filter(run=run).first()
        return [] if review is None else [f"Node {review.version}: {review.executable}"]


HANDLER = RuntimeHandler()
