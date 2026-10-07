"""Only this module writes a site plan's own rows, in the transaction that saves the plan."""

from bootstrap.models import ConfigurationPlan

from .admission import SiteDraft
from .models import (
    PlanAccountChange,
    PlanDirectoryChange,
    PlanFileChange,
    PlanSite,
    PlanSiteName,
)


def save_site(plan: ConfigurationPlan, draft: SiteDraft) -> None:
    paths = draft.paths
    if paths is None:
        return
    PlanSite.objects.create(
        plan=plan,
        identifier=paths.identifier,
        php_version=paths.php,
        convention_revision=paths.revision,
        user=paths.user,
        document_root=paths.public,
        socket=paths.socket,
        pool_name=paths.identifier,
        ipv6=draft.ipv6,
        probe_token=draft.token,
        payload_bytes=draft.payload_bytes,
    )
    PlanSiteName.objects.bulk_create(
        PlanSiteName(plan=plan, position=position, name=name)
        for position, name in enumerate(draft.names)
    )
    PlanFileChange.objects.bulk_create(
        PlanFileChange(
            plan=plan,
            position=position,
            role=item.role,
            path=item.path,
            file_type=item.file_type,
            owner=item.owner,
            group=item.group,
            mode=item.mode,
            link_target=item.link_target,
            content=item.content,
            content_sha256=item.sha256,
            temporary=item.temporary,
            preimage_absent=item.path not in draft.retained,
        )
        for position, item in enumerate(draft.files)
        if item.role != "placeholder" or item.path not in draft.retained
    )
    PlanDirectoryChange.objects.bulk_create(
        PlanDirectoryChange(
            plan=plan,
            position=position,
            path=item.path,
            owner=item.owner,
            group=item.group,
            mode=item.mode,
        )
        for position, item in enumerate(draft.directories)
    )
    account = draft.account
    if account is not None and draft.files:
        PlanAccountChange.objects.create(
            plan=plan,
            user=account.user,
            group=account.user,
            home=account.home,
            login_shell="/usr/sbin/nologin",
            command=account.command,
            uid_min=account.uid_range[0],
            uid_max=account.uid_range[1],
            gid_min=account.gid_range[0],
            gid_max=account.gid_range[1],
            free_uids=account.free_uids,
            free_gids=account.free_gids,
            predicted_uid=account.predicted_uid,
            predicted_gid=account.predicted_gid,
            subordinate_ids=account.subordinate_ids,
        )
