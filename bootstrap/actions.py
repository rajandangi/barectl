"""Actions other apps add to configuration plans (docs/ssh-connections.md#site-preparation).

Bootstrap's own actions keep their built-in review and apply paths. Another app registers a
handler for its actions from its ``AppConfig.ready``; bootstrap asks the registry, and never
imports that app, whenever preparation, saving, presentation, permissions or applying
depend on the action.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from django.contrib.auth.models import AnonymousUser, User

from discovery.ssh import RemoteShell

from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanPreparation,
    Verification,
)
from .native import UnitEvidence
from .review import Draft

_VIEW = ("servers.view_server", "bootstrap.view_configurationplan")


@dataclass(frozen=True)
class Authority:
    """The Barectl permissions each stage of an action's plans requires."""

    view: tuple[str, ...]
    prepare: tuple[str, ...]
    apply: tuple[str, ...]


BOOTSTRAP_ACTIONS = frozenset({Action.NGINX, Action.PHP, Action.METADATA_REFRESH})
BOOTSTRAP = Authority(
    view=_VIEW,
    prepare=(*_VIEW, "bootstrap.prepare_configurationplan"),
    apply=(*_VIEW, "bootstrap.apply_configurationplan"),
)
CLEANUP = Authority(
    view=_VIEW,
    prepare=BOOTSTRAP.prepare,
    apply=(*_VIEW, "bootstrap.clear_native_results"),
)
# The actions bootstrap reviews and applies itself.
BUILT_IN = frozenset({*BOOTSTRAP_ACTIONS, Action.CLEAR_RESULTS})


class ActionHandler(Protocol):
    @property
    def actions(self) -> frozenset[str]: ...

    @property
    def authority(self) -> Authority: ...

    @property
    def applicable(self) -> bool:
        """Whether an eligible plan with changes may be applied."""
        ...

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        """Inspect the server read-only and review ``preparation``'s request."""
        ...

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        """Store the action's own plan rows; called in the transaction that saves ``plan``."""
        ...

    def prefetch(self) -> tuple[str, ...]:
        """The plan's related names its review reads."""
        ...

    def review(self, plan: ConfigurationPlan) -> object:
        """The action's own review details, which its template ``review_template`` shows."""
        ...

    @property
    def review_template(self) -> str: ...

    # Applying (docs/ssh-connections.md#applying-sites) --------------------------------

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        """The plan's changes, one per line, copied to the run's audit."""
        ...

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        """Copy the plan's typed changes to ``run``; called in the transaction queueing it."""
        ...

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        """The run's payload; raises ``OperationRefused`` when it cannot be built."""
        ...

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        """Check, before submission, what verifying the run will need; raises
        ``OperationRefused`` otherwise."""
        ...

    def execution(self, evidence: UnitEvidence) -> Execution:
        """What the unit's terminal evidence established for this action."""
        ...

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification: ...

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        """Why a run that did not succeed failed, with ordinary-administration recovery."""
        ...

    def verification_failure(self, run: ApplyRun) -> str: ...

    def audit(self, run: ApplyRun) -> list[str]:
        """What the run's own records add to its audit, one line each."""
        ...


_HANDLERS: dict[str, ActionHandler] = {}


def register_handler(handler: ActionHandler) -> None:
    for action in handler.actions:
        if action in BUILT_IN:
            raise ValueError(f"{action} is reviewed by bootstrap itself.")
        _HANDLERS[action] = handler


def extension(action: str) -> ActionHandler | None:
    """The handler of ``action``, or ``None`` for bootstrap's own actions."""
    return _HANDLERS.get(action)


def authority(action: str) -> Authority:
    handler = extension(action)
    if handler is not None:
        return handler.authority
    return CLEANUP if action == Action.CLEAR_RESULTS else BOOTSTRAP


def applicable(action: str) -> bool:
    handler = extension(action)
    return handler is None or handler.applicable


def visible(user: User | AnonymousUser, actions: Iterable[str]) -> list[str]:
    """Those of ``actions`` whose plans and runs ``user`` may view."""
    return [action for action in actions if user.has_perms(authority(action).view)]


def every_action() -> list[str]:
    return [action.value for action in Action]


def prefetches() -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(name for handler in _HANDLERS.values() for name in handler.prefetch())
    )
