"""The privileged, read-only inspection of site database bindings
(docs/databases.md#privileged-inspection).

Discovery never escalates, so a lesser SSH identity sees catalogs as inaccessible. This
preparation, which only accounts allowed to prepare database plans may request, repeats
discovery's reads as root, through noninteractive sudo when the SSH user is not root, and
keeps what it read with the plan. It is never merged into discovery.
"""

from dataclasses import dataclass, field

from bootstrap import inspection as bootstrap_inspection
from bootstrap import native as bootstrap_native
from bootstrap.inspection import Reader
from bootstrap.models import Action, PlanEffect, PlanRefusal, Privilege
from bootstrap.releases import of as release_of
from bootstrap.review import Draft, check_platform
from discovery.observations import collect
from discovery.snapshot import ObservedDatabase
from discovery.ssh import CommandResult, RemoteShell
from sites.native import script

Reason = PlanRefusal.Reason
INTENT = "Read every site's database binding from the engines' catalogs, as root, changing nothing."


@dataclass
class InspectionDraft(Draft):
    # Each site candidate with what the catalogs hold under its name.
    observations: list[tuple[str, ObservedDatabase]] = field(default_factory=list)


class _AsRoot:
    """A shell that runs every read as root, as discovery's commands under ``sh -c``."""

    def __init__(self, shell: RemoteShell, *, root: bool) -> None:
        self.shell = shell
        self.root = root
        self.host_key = shell.host_key

    def run(self, command: str) -> CommandResult:
        if self.root:
            return self.shell.run(command)
        return self.shell.run(bootstrap_native.privileged(script(command), root=False))


def prepare(shell: RemoteShell) -> InspectionDraft:
    reader = Reader(shell)
    platform = bootstrap_inspection.read_platform(reader)
    release = release_of(platform.os) if platform is not None else None
    draft = InspectionDraft(Action.DATABASE_INSPECTION, INTENT, platform, release)
    check_platform(draft, platform)
    for gap in reader.gaps:
        draft.refuse(Reason.INCOMPLETE, gap)
    if platform is None or release is None:
        return draft
    root = platform.privilege == Privilege.ROOT
    probe = script("id -u")
    if not root and shell.run(bootstrap_native.authorization(probe)).exit_status != 0:
        draft.refuse(
            Reason.PRIVILEGE,
            "The SSH user is not root, and sudo -n -l does not authorize Barectl's read-only "
            "inspection scripts without a password, so the catalogs stay inaccessible. The "
            "permission to prepare database plans is the explicit authority for that read. "
            "Barectl never installs a sudo policy or asks for a password.",
        )
        return draft
    collected = collect(_AsRoot(shell, root=root))
    sites = collected.sites
    draft.observations = [
        (site.identifier, site.database) for site in sites.value if site.database is not None
    ]
    how = "as root" if root else "through noninteractive sudo"
    draft.effects.append(
        (
            PlanEffect.Kind.CATALOG_INSPECTION,
            (
                f"Read {len(draft.observations)} site candidates' catalog rows {how}, with "
                "discovery's fixed read-only commands, each under sh -c. "
                "Nothing was changed, and nothing here updates discovery; the result is kept only "
                "with this plan."
            ),
        )
    )
    return draft
