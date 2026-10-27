"""The printable recovery kit: non-secret facts that make a repository openable later.

The kit names the server, the repository path, the restic version and the plain commands to
list and restore. It never holds the recovery passphrase, a storage key or any other secret
(#358).
"""

from . import convention


def lines(
    *,
    server_name: str,
    identifier: str,
    restic_version: str,
    provider: str = "",
    endpoint: str = "",
    bucket: str = "",
    prefix: str = "",
    sites: tuple[str, ...] = (),
) -> list[str]:
    """The kit's exact lines for one installation, without any secret."""
    repository = convention.repository(identifier)
    rows = []
    if server_name:
        rows.append(f"Server: {server_name}")
    rows.extend(
        (
            f"Site: {identifier}",
            f"Backup tool: restic {restic_version}" if restic_version else "Backup tool: restic",
            f"Onsite repository: {repository}",
        )
    )
    if provider:
        rows.extend(
            (
                f"Offsite storage: {provider}",
                f"Endpoint: {endpoint}",
                f"Bucket: {bucket}",
                f"Prefix: {prefix}",
            )
        )
    else:
        rows.append("Offsite storage: not configured")
    if len(sites) > 1:
        rows.append("Site repositories:")
        rows.extend(f"  {site}: {convention.repository(site)}" for site in sites)
    rows.extend(
        (
            "",
            "Open it on any machine with restic and the recovery passphrase:",
            f'  export RESTIC_REPOSITORY="{repository}"',
            "  restic snapshots",
            "  restic restore latest --target /tmp/restored-site",
            "",
            "A database-only recovery point restores to a .sql file:",
            "  restic dump latest s<id>.sql > database.sql",
            "",
            "The recovery passphrase is not in this kit. Keep it somewhere else.",
        )
    )
    return rows
