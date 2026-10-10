"""Plain progress labels for the normal hosting workflow."""

from dataclasses import dataclass

from bootstrap.models import Action

from .creation import CreationView

_LABELS = {
    "discover": "Check server and site",
    Action.METADATA_REFRESH: "Check available software",
    Action.PHP_SOURCE_PREREQUISITES: "Prepare software tools",
    Action.PHP_LIBRARIES: "Prepare PHP requirements",
    Action.PHP_SOURCE: "Prepare PHP versions",
    Action.NGINX: "Set up web server",
    Action.PHP: "Set up PHP",
    Action.MARIADB: "Set up MariaDB",
    Action.POSTGRESQL: "Set up PostgreSQL",
    Action.PHP_MYSQL: "Enable PHP database access",
    Action.PHP_PGSQL: "Enable PHP database access",
    Action.SITE_HTTP: "Create isolated site",
    Action.NODE_RUNTIME: "Set up Node",
    Action.PHP_WORDPRESS: "Enable WordPress requirements",
    Action.WORDPRESS_LIBRARIES: "Prepare WordPress libraries",
    Action.DATABASE_MARIADB: "Create site database",
    Action.DATABASE_POSTGRESQL: "Create site database",
    Action.TLS_CHALLENGE: "Prepare HTTPS validation",
    Action.CERTBOT: "Set up certificate tools",
    Action.TLS_ISSUANCE: "Request HTTPS certificate",
    Action.TLS_ACTIVATION: "Enable HTTPS",
    Action.WPCLI: "Set up WordPress tools",
    Action.WORDPRESS_INSTALL: "Install WordPress",
    Action.PHP_DEFAULT: "Set default PHP version",
    Action.SITE_PHP_SWITCH: "Change site PHP version",
}
_STATUSES = {
    "active": "In progress",
    "succeeded": "Complete",
    "failed": "Stopped",
    "satisfied": "Ready",
    "pending": "Waiting",
    "queued": "Waiting",
    "running": "In progress",
    "reconciling": "Checking result",
}


@dataclass(frozen=True)
class Step:
    label: str
    status: str
    failure: str


def stage_label(stage: str) -> str:
    return _LABELS.get(stage, "Prepare required software")


def status_label(status: str) -> str:
    return _STATUSES.get(status, "Checking progress")


def creation_progress(creation: CreationView | None) -> dict[str, object]:
    return {
        "hosting_status": status_label(creation.status) if creation else "",
        "hosting_steps": tuple(
            Step(stage_label(step.stage), status_label(step.status), step.failure)
            for step in creation.steps
        )
        if creation
        else (),
    }
