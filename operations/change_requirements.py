"""The one requirement registry for every change kind (spec #507, #510-#515).

Cards, the generic prepare POST and the "prepare again" path all read the same constant
from here, so a card and its POST cannot drift. A slug without a specific entry falls back
to a plain server change, which is the safest default: it asks for the prepare permission
and the host's standing/freshness, and never assumes a target stack or a site.

The registry names the requirements only; ``operations.preparation`` remains the pure
decision and the area modules remain the owners of their card wording.
"""

from collections.abc import Mapping
from dataclasses import replace

from backups.preparation import BASE as BACKUP_BASE
from backups.preparation import DESTRUCTIVE as BACKUP_DESTRUCTIVE
from backups.preparation import ENABLE as BACKUP_ENABLE
from backups.preparation import EXPORT as BACKUP_EXPORT
from backups.preparation import REOPEN as BACKUP_REOPEN
from operations import preparation
from sites.bodies.common import NODE_INTERRUPTED, PHP_TRANSITION_INCOMPLETE

# A plain server change: setup and cleanup may run before the target stack exists.
HOST_FOUNDATION = preparation.SERVER
SERVER_CHANGE = preparation.SERVER

# A server-wide change that assumes the host was read and is on the target stack.
TARGET_SERVER = replace(preparation.SERVER, target_stack=True)
DATABASE = TARGET_SERVER
CERTIFICATE_EMAIL = TARGET_SERVER
ADD_RUNTIME = TARGET_SERVER
RUNTIME_DEFAULTS = TARGET_SERVER
OBJECT_CACHE = replace(TARGET_SERVER, needs=TARGET_SERVER.needs | {preparation.Need.SHARED})
SECURITY = OBJECT_CACHE
# The journal retention kind lands with #551; the shared requirement is declared now so its
# card and prepare read one constant.
JOURNAL_RETENTION = replace(TARGET_SERVER, needs=TARGET_SERVER.needs | {preparation.Need.SHARED})
# Registry entries whose kind is not registered yet, so the registry test names exactly the
# forward declaration rather than allowing any unknown slug (#549 lands the entry, #551 the kind).
PENDING_KINDS: frozenset[str] = frozenset({"set_journal_retention"})
BACKUP_STORAGE = replace(
    TARGET_SERVER,
    needs=frozenset({preparation.Need.CHANGE, preparation.Need.SITE, preparation.Need.SECRET}),
)

# Creating a site is a server-wide change: the site does not exist yet, so it asks for the
# target stack and both site permissions. WordPress also writes the administrator secret.
CREATE_SITE = replace(
    TARGET_SERVER,
    needs=TARGET_SERVER.needs | {preparation.Need.SITE},
)
CREATE_WORDPRESS_SITE = replace(CREATE_SITE, needs=CREATE_SITE.needs | {preparation.Need.SECRET})

# Site Settings and their own completion rules.
SITE_PHP = replace(preparation.SITE, state=None, completes=PHP_TRANSITION_INCOMPLETE)
SITE_NODE = replace(preparation.SITE, state=None, completes=NODE_INTERRUPTED)
SITE_POOL = replace(preparation.SITE, pool=True)
SITE_READINESS = replace(preparation.SITE, releases_observed=True, no_releases=True)
SITE_DOMAINS = preparation.SITE
SITE_DATABASE = preparation.SITE
SITE_REMOVE = preparation.Requirements(
    target_stack=True,
    site=True,
    convention=False,
    allow_not_following=True,
    needs=frozenset({preparation.Need.CHANGE, preparation.Need.SITE}),
)
SITE_CACHE_ON = replace(preparation.SITE, cache=True)
SITE_CACHE_OFF = replace(
    preparation.SITE,
    state=None,
    allow_partly_applied=True,
    cache=True,
)

# Automation, WordPress and Laravel.
WORDPRESS_TASKS = replace(preparation.SITE, application="wordpress", no_application_problem=True)
LARAVEL_TASKS = replace(preparation.SITE, application="laravel", no_application_problem=True)
LARAVEL_WORKERS = replace(
    preparation.SITE,
    state=None,
    application="laravel",
    current_release=True,
    open_site=True,
)
WORDPRESS_PASSWORD = replace(
    WORDPRESS_TASKS,
    needs=WORDPRESS_TASKS.needs | {preparation.Need.SECRET},
)
WORDPRESS_CORE = WORDPRESS_TASKS
WORDPRESS_SETTINGS = WORDPRESS_PASSWORD
LARAVEL_ENVIRONMENT = replace(
    LARAVEL_TASKS,
    needs=LARAVEL_TASKS.needs | {preparation.Need.SECRET},
)
LARAVEL_DEPLOY = replace(
    preparation.SITE,
    application="laravel",
    releases_observed=True,
    current_release=True,
    open_site=True,
)
LARAVEL_ROLLBACK = replace(
    preparation.SITE,
    application="laravel",
    releases_observed=True,
    retained_release=True,
    open_site=True,
)

LOG_ROTATION = replace(preparation.SITE, rotation_unsupported=True)

# The registry keyed by the change-kind slug the preparation stores.
REQUIREMENTS: Mapping[str, preparation.Requirements] = {
    # Server settings and setup.
    "host_foundation": HOST_FOUNDATION,
    "cleanup_runs": SERVER_CHANGE,
    "add_runtime": ADD_RUNTIME,
    "update_catalog": ADD_RUNTIME,
    "revert_runtime": ADD_RUNTIME,
    "remove_runtime": ADD_RUNTIME,
    "set_default_php": RUNTIME_DEFAULTS,
    "set_default_node": RUNTIME_DEFAULTS,
    "install_database_engine": DATABASE,
    "remove_database_engine": DATABASE,
    "install_valkey": OBJECT_CACHE,
    "check_for_ubuntu_updates": SECURITY,
    "install_ubuntu_updates": SECURITY,
    "set_automatic_security_updates": SECURITY,
    "manage_firewall": SECURITY,
    "require_key_sign_in": SECURITY,
    "restart_server": SECURITY,
    "set_certificate_email": CERTIFICATE_EMAIL,
    "set_up_offsite_storage": BACKUP_STORAGE,
    "remove_offsite_storage": BACKUP_STORAGE,
    "connect_existing_backup_storage": BACKUP_STORAGE,
    "replace_recovery_passphrase": BACKUP_STORAGE,
    # Creating a site.
    "create_http_site": CREATE_SITE,
    "create_laravel_site": CREATE_SITE,
    "create_wordpress_site": CREATE_WORDPRESS_SITE,
    # Site settings.
    "set_site_php": SITE_PHP,
    "set_site_node": SITE_NODE,
    "set_site_pool": SITE_POOL,
    "set_site_readiness": SITE_READINESS,
    "set_site_domains": SITE_DOMAINS,
    "remove_site": SITE_REMOVE,
    "add_site_database": SITE_DATABASE,
    "set_site_object_cache": SITE_CACHE_ON,
    "set_site_php_client": SITE_CACHE_ON,
    # Automation, WordPress and Laravel.
    "set_wordpress_server_cron": WORDPRESS_TASKS,
    "set_laravel_scheduler": LARAVEL_TASKS,
    "set_laravel_queue_workers": LARAVEL_WORKERS,
    "reset_wordpress_password": WORDPRESS_PASSWORD,
    "verify_wordpress_core": WORDPRESS_CORE,
    "edit_wordpress_settings": WORDPRESS_SETTINGS,
    "edit_laravel_environment": LARAVEL_ENVIRONMENT,
    "deploy_laravel_site": LARAVEL_DEPLOY,
    "rollback_laravel_site": LARAVEL_ROLLBACK,
    # Backups.
    "enable_backups": BACKUP_ENABLE,
    "back_up_now": BACKUP_BASE,
    "back_up_full_site": BACKUP_BASE,
    "reopen_site": BACKUP_REOPEN,
    "restore_database": BACKUP_DESTRUCTIVE,
    "set_backup_retention": BACKUP_DESTRUCTIVE,
    "disable_backup_retention": BACKUP_BASE,
    "keep_recovery_point": BACKUP_BASE,
    "delete_removed_backups": BACKUP_DESTRUCTIVE,
    "export_recovery_point": BACKUP_EXPORT,
    "copy_offsite_again": BACKUP_BASE,
    "set_backup_schedule": BACKUP_BASE,
    # Logs.
    "set_up_log_rotation": LOG_ROTATION,
    "set_journal_retention": JOURNAL_RETENTION,
}


def requirements_for(
    kind_slug: str, inputs: Mapping[str, object] | None = None
) -> preparation.Requirements:
    """The card's requirement set for one kind, plus its declared secret need.

    ``set_site_object_cache`` covers both turning a cache on and off; the stored inputs say
    which card admitted the change. A kind that writes a secret adds ``Need.SECRET`` unless
    its card already names it.
    """
    from operations.engine import kind_of

    requirements = REQUIREMENTS.get(kind_slug, SERVER_CHANGE)
    if (
        kind_slug == "set_site_object_cache"
        and inputs is not None
        and inputs.get("object_cache") is False
    ):
        requirements = SITE_CACHE_OFF
    kind = kind_of(kind_slug)
    if kind is not None and kind.writes_secrets:
        requirements = replace(requirements, needs=requirements.needs | {preparation.Need.SECRET})
    return requirements
