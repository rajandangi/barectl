"""Only this module writes a WordPress runtime plan's own rows, in the transaction that saves
the plan."""

from bootstrap.models import ConfigurationPlan
from databases.plans import save_driver
from sites.convention import SitePaths

from . import runtime
from .models import PlanRuntimeCapability, PlanWordpressRuntime


def save_runtime(plan: ConfigurationPlan, draft: runtime.RuntimeDraft) -> None:
    save_driver(plan, draft)
    if not draft.capabilities or draft.site_uid <= 0 or not draft.php_version:
        return
    paths = SitePaths(draft.identifier, draft.php_version, revision=draft.site_revision)
    content = runtime.render_probe(draft.token)
    PlanWordpressRuntime.objects.create(
        plan=plan,
        identifier=draft.identifier,
        php_version=draft.php_version,
        php_supply=draft.php_supply,
        site_revision=draft.site_revision,
        site_user=paths.user,
        uid=draft.site_uid,
        gid=draft.site_gid,
        socket=paths.socket,
        probe_token=draft.token,
        probe_path=runtime.probe_path(draft.identifier, draft.token),
        probe_content=content,
        probe_sha256=runtime.digest(content),
    )
    PlanRuntimeCapability.objects.bulk_create(
        PlanRuntimeCapability(
            plan=plan,
            position=position,
            name=item.name,
            label=item.label,
            package=item.package,
            cli=item.cli,
            fpm=item.fpm,
            state=item.state,
        )
        for position, item in enumerate(draft.capabilities)
    )
