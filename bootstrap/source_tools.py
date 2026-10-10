"""Source prerequisites through the existing authenticated package profile."""

from dataclasses import dataclass

from discovery.ssh import RemoteShell

from . import inspection, profiles, review
from .models import Action, ConfigurationPlan, PlanPreparation, PlanRefusal
from .runtime_services import PhpRuntimeObservation, observe_php_runtime
from .source_tools_models import SourceToolsSelection


@dataclass
class ToolsDraft(review.Draft):
    selection: PhpRuntimeObservation | None = None
    selected_supply: str = ""


def inspect(shell: RemoteShell, preparation: PlanPreparation) -> ToolsDraft:
    from node_runtimes.models import RuntimeChangeStep

    node_only = RuntimeChangeStep.objects.filter(preparation=preparation).exists()
    observed = None if node_only else observe_php_runtime(shell)
    evidence = inspection.inspect(shell, Action.PHP_SOURCE_PREREQUISITES)
    reviewed = review.review(Action.PHP_SOURCE_PREREQUISITES, evidence)
    draft = ToolsDraft(**reviewed.__dict__, selection=observed)
    if reviewed.no_changes:
        release = reviewed.release
        if release is not None:
            check = shell.run(profiles.source_tools(release).check.command)
            if check.exit_status or check.truncated:
                draft.refuse(
                    PlanRefusal.Reason.INCOMPLETE,
                    "Installed source tools are unavailable; "
                    "repair the native package installation.",
                )
    if observed is None:
        return draft
    if observed.failure or observed.supply not in {"ubuntu", "sury"}:
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE,
            observed.failure or "PHP supply could not be established.",
        )
        return draft
    draft.selected_supply = observed.supply
    return draft


def save(plan: ConfigurationPlan, draft: ToolsDraft) -> None:
    observed = draft.selection
    if draft.eligible and observed is not None:
        SourceToolsSelection.objects.create(
            plan=plan,
            supply=draft.selected_supply,
            installed=bool(observed.installed),
            default_branch=observed.default.branch if observed.default else "",
            fingerprint=observed.fingerprint,
        )
