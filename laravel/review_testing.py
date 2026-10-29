"""Deploy and Roll back evidence and reviews shared by the fast and browser tests."""

from backups.observation import BackupResult, ObservedBackup
from bootstrap.standing import Standing
from laravel import change, rollback
from operations.engine import ReviewDraft
from operations.inputs import PreparationInputs
from runtimes.catalog import Architecture
from sites.bodies.common import SiteRecord

REPOSITORY = "https://github.com/example/app.git"
BOOT = "00000000-0000-0000-0000-000000000000"


def release(index: int, *, created: int | None = None) -> dict[str, object]:
    commit = f"{index:040x}"
    return {
        "name": f"{commit}-{'a' * 16}",
        "commit": commit,
        "created": created if created is not None else 1000 - index,
        "state": "complete",
        "repository": REPOSITORY,
        "branch": "main",
    }


def releases_in(row: dict[str, object]) -> list[dict[str, object]]:
    value = row["releases"]
    if not isinstance(value, list):
        raise TypeError("A Laravel row holds a release list.")
    return [item for item in value if isinstance(item, dict)]


def laravel_row(identifier: str = "s4alpha", count: int = 7) -> dict[str, object]:
    releases = [release(index) for index in range(count)]
    return {
        "identifier": identifier,
        "application": "laravel",
        "current": releases[0]["name"],
        "repository": REPOSITORY,
        "branch": "main",
        "php_requirement": "",
        "repository_problem": "",
        "releases": releases,
        "shared": {"environment": True, "storage": True, "cache": True},
        "environment": ["APP_ENV", "APP_KEY"],
        "deploy_key": "",
        "host_keys": False,
        "problem": "",
    }


def site_record(identifier: str = "s4alpha") -> SiteRecord:
    return {
        "identifier": identifier,
        "names": [f"{identifier}.example.com"],
        "runtime": "php84",
        "node_runtime": "",
        "https": True,
        "readiness": "/",
        "certificate": None,
        "pool": None,
        "account": [4000, 4000, f"/var/www/{identifier}", "/usr/sbin/nologin", [4000]],
        "file": f"/etc/caddy/sites/{identifier}.caddy",
        "state": "complete",
        "problem": "",
        "application": "laravel",
        "application_version": "",
        "application_problem": "",
        "serving_form": "",
    }


def deploy_evidence(
    identifier: str = "s4alpha",
    *,
    pending: tuple[str, ...] | None = (),
    backup: ObservedBackup | None = None,
) -> change.DeployEvidence:
    return change.DeployEvidence(
        Standing.TARGET_STACK,
        Architecture.X86_64,
        10 * 1024 * 1024 * 1024,
        BOOT,
        500,
        site_record(identifier),
        laravel_row(identifier),
        "b" * 40,
        True,
        "",
        pending,
        backup,
    )


def backup(
    identifier: str = "s4alpha",
    *,
    enabled: bool = True,
    result: BackupResult | None = None,
) -> ObservedBackup:
    """One site's backup setup, as the Deploy review reads it."""
    return ObservedBackup(
        identifier,
        "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1" if enabled else "",
        enabled,
        enabled,
        (),
        True,
        "",
        result,
    )


def deploy_draft(
    identifier: str = "s4alpha",
    *,
    migrations: bool = True,
    pending: tuple[str, ...] | None = (),
    backup_result: BackupResult | None = None,
) -> ReviewDraft:
    return change.review(
        deploy_evidence(
            identifier,
            pending=pending,
            backup=backup(identifier, result=backup_result) if pending else None,
        ),
        PreparationInputs("", identifier, migrations=migrations),
    )


def rollback_evidence(identifier: str = "s4alpha") -> rollback.RollbackEvidence:
    return rollback.RollbackEvidence(
        Standing.TARGET_STACK,
        Architecture.X86_64,
        BOOT,
        500,
        site_record(identifier),
        laravel_row(identifier),
    )


def rollback_draft(identifier: str, release_name: str) -> ReviewDraft:
    return rollback.review(
        rollback_evidence(identifier), PreparationInputs("", identifier, (), release_name)
    )
