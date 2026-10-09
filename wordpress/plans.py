"""Only this module writes a WordPress runtime plan's own rows, in the transaction that saves
the plan."""

from bootstrap.models import ConfigurationPlan
from databases.plans import save_driver
from sites.convention import SitePaths

from . import inspection, install, runtime
from .inspection_models import PlanWordpressInspection
from .models import PlanRuntimeCapability, PlanWordpressInstall, PlanWordpressRuntime


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


def save_install(plan: ConfigurationPlan, draft: install.InstallDraft) -> None:
    """The reviewed installation, as an apply run consumes it. A refused review keeps no row:
    only a fully bound review can be applied."""
    if not draft.ready or draft.paths is None:
        return
    PlanWordpressInstall.objects.create(plan=plan, **install.install_fields(draft))


def save_inspection(plan: ConfigurationPlan, draft: inspection.InspectionDraft) -> None:
    """The reviewed inspection, as an apply run consumes it. A refused review keeps no row:
    only a fully bound review can be applied."""
    if not draft.ready or draft.paths is None:
        return
    PlanWordpressInspection.objects.create(plan=plan, **inspection.inspection_fields(draft))
