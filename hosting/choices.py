"""Visible runtime choices follow the observed native supply and qualification."""

from django import forms

from bootstrap import php_supply
from bootstrap.models import PhpRuntimeSnapshot
from discovery.models import ApplicationState, SiteRouting
from discovery.releases import SUPPORTED
from servers.discovery_state import DiscoveryState
from wordpress import qualification


def is_wordpress(state: DiscoveryState, identifier: str) -> bool:
    if state.snapshot is None:
        return False
    return any(
        site.identifier == identifier
        and (
            site.routing in {SiteRouting.WORDPRESS, SiteRouting.WORDPRESS_GATE}
            or (site.application is not None and site.application.state != ApplicationState.ABSENT)
        )
        for site in state.snapshot.collected.sites.value
    )


def php_branches(
    state: DiscoveryState, observed: PhpRuntimeSnapshot | None, *, wordpress: bool = False
) -> tuple[str, ...]:
    if state.snapshot is None or observed is None or observed.failure:
        return ()
    platform = state.snapshot.collected
    release = platform.os.value
    supported = SUPPORTED.get(release.version_id) if release is not None else None
    if supported is None or observed.supply not in {"ubuntu", "sury"}:
        return ()
    branches = (supported.php,) if observed.supply == "ubuntu" else php_supply.ELIGIBLE_BRANCHES
    architecture = qualification.architecture_of(platform.architecture.value or "")
    return tuple(
        branch
        for branch in branches
        if not wordpress
        or qualification.qualified(supported.version, architecture, branch, observed.supply)
    )


def default_php_branch(state: DiscoveryState, observed: PhpRuntimeSnapshot | None) -> str:
    if state.snapshot is None or observed is None:
        return ""
    release = state.snapshot.collected.os.value
    supported = SUPPORTED.get(release.version_id) if release is not None else None
    return observed.default_branch or (supported.php if supported is not None else "")


def set_php_choices(
    form: forms.Form, field: str, branches: tuple[str, ...], *, default_allowed: bool = True
) -> None:
    selected = form.fields[field]
    if not isinstance(selected, forms.ChoiceField):
        raise TypeError("PHP selection must be a choice field.")
    if field == "php_version" and not default_allowed:
        selected.required = True
    empty = "Use server default" if field == "php_version" else "Choose a PHP version"
    selected.choices = (
        *((("", empty),) if default_allowed else ()),
        *((branch, f"PHP {branch}") for branch in branches),
    )
