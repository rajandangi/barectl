"""Server Settings > Backup storage, from the latest observation only (Phase D #403).

Opening the section makes no SSH connection. The panel shows the non-secret offsite fields
passive discovery read; the access keys never appear here.
"""

from dataclasses import dataclass
from typing import Final

from django.contrib.auth.models import AnonymousUser, User

from backups import convention
from backups.observation import OffsiteStorage
from discovery.presentation import VIEW_SITES
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from operations.models import MANAGE_SECRETS

from .discovery_state import DiscoveryState
from .models import Server

SETUP_KIND: Final = "set_up_offsite_storage"
REMOVE_KIND: Final = "remove_offsite_storage"


@dataclass(frozen=True)
class BackupStoragePanel:
    observed: bool
    configured: bool
    provider: str
    provider_label: str
    bucket: str
    region: str
    endpoint: str
    prefix: str
    prune: bool
    outside: tuple[str, ...]
    note: str


def panel(storage: OffsiteStorage | None, observed: bool) -> BackupStoragePanel:
    if not observed:
        return BackupStoragePanel(
            False,
            False,
            "",
            "",
            "",
            "",
            "",
            "",
            False,
            (),
            "Check the connection to read this server's backup storage.",
        )
    if storage is None:
        return BackupStoragePanel(
            True, False, "", "", "", "", "", "", False, (), "No offsite storage is connected."
        )
    if storage.problem:
        return BackupStoragePanel(
            True,
            False,
            "",
            "",
            "",
            "",
            "",
            "",
            False,
            (storage.problem,),
            "Offsite storage needs ordinary administration before Barectl changes backups.",
        )
    return BackupStoragePanel(
        True,
        storage.configured,
        storage.provider,
        storage.label,
        storage.bucket,
        storage.region,
        storage.endpoint,
        storage.prefix,
        storage.prune,
        (),
        "Offsite copies are encrypted by restic and the keys stay only on this server.",
    )


def context_for_server(
    server: Server, user: User | AnonymousUser, state: DiscoveryState
) -> dict[str, object]:
    snapshot = state.snapshot
    observed = snapshot is not None and snapshot.collected.offsite.observed
    value = snapshot.collected.offsite.value if snapshot is not None else None
    polling = services.read_changes(server).polling
    return {
        "backup_storage_panel": panel(
            value if isinstance(value, OffsiteStorage) else None, observed
        ),
        "backup_storage_can_prepare": bool(
            observed
            and state.can_prepare_changes
            and not polling
            and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES, MANAGE_SECRETS))
        ),
        "backup_storage_setup_kind": SETUP_KIND,
        "backup_storage_remove_kind": REMOVE_KIND,
        "backup_storage_providers": tuple(
            (provider, convention.PROVIDER_LABELS[provider]) for provider in convention.PROVIDERS
        ),
    }
