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
    region: str = "",
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
    offsite_repository = ""
    if provider:
        config = {
            "provider": {
                "Amazon S3": "s3",
                "Cloudflare R2": "r2",
            }.get(provider, provider),
            "bucket": bucket,
            "region": region,
            "endpoint": endpoint,
            "prefix": prefix,
            "prune": "no",
        }
        try:
            offsite_repository = convention.offsite_repository(config, identifier)
        except ValueError:
            offsite_repository = ""
        rows.extend(
            (
                f"Offsite storage: {provider}",
                f"Endpoint: {endpoint}",
                f"Bucket: {bucket}",
                f"Prefix: {prefix}",
            )
        )
        if region:
            rows.append(f"Region: {region}")
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
        )
    )
    if offsite_repository:
        rows.extend(
            (
                "",
                "Open the offsite copy with restic, the recovery passphrase and the storage",
                "keys you stored, and the same commands:",
                f'  export RESTIC_REPOSITORY="{offsite_repository}"',
                *((f'  export AWS_DEFAULT_REGION="{region}"',) if region else ()),
                "  restic -o s3.bucket-lookup=path snapshots",
                "  restic -o s3.bucket-lookup=path restore latest --target /tmp/restored-site",
                "  restic -o s3.bucket-lookup=path dump latest s<id>.sql > database.sql",
            )
        )
    rows.extend(
        (
            "",
            (
                "The recovery passphrase and the storage keys are not in this kit. Keep them "
                "somewhere else."
            ),
        )
    )
    return rows
