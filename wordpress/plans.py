"""Only this module writes a WordPress runtime plan's own rows, in the transaction that saves
the plan."""

from bootstrap.models import ConfigurationPlan
from databases.plans import save_driver
from sites.convention import SitePaths

from . import convention, core_native, install, runtime, setup_native
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
    paths = draft.paths
    if not draft.ready or paths is None:
        return
    identifier, wanted = draft.identifier, draft.wanted
    PlanWordpressInstall.objects.create(
        plan=plan,
        identifier=identifier,
        php_version=draft.php_version,
        php_supply=draft.php_supply,
        site_revision=draft.site_revision,
        site_user=paths.user,
        uid=draft.uid,
        gid=draft.gid,
        socket=paths.socket,
        ipv6=draft.ipv6,
        names=" ".join(draft.names),
        canonical_name=wanted.canonical_name,
        url=f"https://{wanted.canonical_name}",
        title=wanted.title,
        admin_login=wanted.admin_login,
        admin_email=wanted.admin_email,
        certificate_sha256=draft.certificate,
        certificate_not_after=draft.not_after,
        tool_version=setup_native.VERSION,
        tool_path=setup_native.PHAR,
        tool_sha256=setup_native.SHA256,
        core_version=core_native.VERSION,
        core_locale=core_native.LOCALE,
        archive_url=core_native.ARCHIVE_URL,
        archive_bytes=core_native.ARCHIVE_BYTES,
        archive_sha256=core_native.ARCHIVE_SHA256,
        max_archive_bytes=core_native.MAX_ARCHIVE_BYTES,
        max_tree_bytes=core_native.MAX_TREE_BYTES,
        max_entries=core_native.MAX_ENTRIES,
        max_file_bytes=core_native.MAX_FILE_BYTES,
        memory_max_bytes=core_native.MEMORY_MAX_BYTES,
        runtime_limit_seconds=core_native.RUNTIME_LIMIT_SECONDS,
        preimage_sha256=install.digest(draft.preimage),
        gate_sha256=install.digest(draft.gate_content),
        gate_content=draft.gate_content,
        ready_sha256=install.digest(draft.ready_content),
        ready_content=draft.ready_content,
        placeholder_sha256=draft.placeholder_sha256,
        placeholder_present=draft.placeholder_present,
        loader_sha256=draft.loader_sha256,
        public_root=convention.public_root(identifier),
        private_configuration=convention.private_configuration_path(identifier),
        database_name=f"s{identifier}",
    )
