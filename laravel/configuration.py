"""Laravel release conventions on the Phase A site layout.

docs/target-architecture.md#laravel and the Phase B specification (#356) define the
convention this module words once:

- a release is ``/var/www/<identifier>/releases/<name>``, built in place as the site user
  and published by root only through the ``current`` link;
- shared state lives outside every release in the site's private area: the ``.env``, the
  application ``storage`` and the generated ``bootstrap/cache``;
- the repository URL and branch are native evidence read from the release's Git metadata,
  never a Barectl marker.
"""

import re
from typing import Final

from sites.configuration import MAINTENANCE_TEMPLATE

# The acknowledgement a Roll back's review requires and a forged apply cannot supply.
ROLLBACK_ACKNOWLEDGEMENT: Final = (
    "I understand a roll back swaps the code only. It does not reverse schema changes, "
    "data, uploads, storage, settings or queued jobs."
)

# How many releases a Deploy keeps besides ``current`` (Phase B settled decision 4).
RETAINED_RELEASES: Final = 5

# The private files the Laravel convention keeps outside every release, in the site's
# private area: the environment, the deploy key pair and the trusted repository host keys
# (Phase B #382, docs/target-architecture.md#laravel).
ENVIRONMENT_FILE: Final = "laravel.env"
DEPLOY_KEY_FILE: Final = "deploy_key"
DEPLOY_KEY_PUBLIC_FILE: Final = "deploy_key.pub"
KNOWN_HOSTS_FILE: Final = "known_hosts"

# The initial release a Create Laravel site publishes before the first Deploy. It carries
# the reviewed repository and branch as native Git metadata (never a Barectl marker) so a
# later Deploy, and a fresh controller, read the same locator from the server's own files.
INITIAL_RELEASE: Final = "initial"

# The operator pastes the repository host's OpenSSH SHA-256 fingerprint, which the review
# matches exactly against the key the server presents (ADR 0034). GitHub documents this at
# https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
FINGERPRINT: Final = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")

# A credential-free ``https://`` URL or a fixed ``user@host:path`` SSH locator; every other
# transport, including URL credentials, ``ext::``, ``file://``, ``ssh://`` and ``git://``,
# is refused (Phase B #382).
_HTTPS_LOCATOR: Final = re.compile(
    r"https://[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?"
    r"(?:/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*)?\Z"
)
_SSH_LOCATOR: Final = re.compile(
    r"[A-Za-z0-9._-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?"
    r":[A-Za-z0-9._~%+@/-]{1,512}\Z"
)
_HTTPS_USERINFO: Final = re.compile(r"https://[^/]*@")
# Git's own ref-name rules, minus the checks that need ``git``: no control byte, space or
# ``~^:?*[\`` anywhere, and no ``..`` or ``@{`` sequence.
_REF: Final = re.compile(r"[^\x00-\x20~^:?*\[\\]{1,255}\Z")
# Laravel's ``key:generate`` output: ``base64:`` and the base64 of 32 random bytes.
APP_KEY: Final = re.compile(r"base64:[A-Za-z0-9+/]{43}=\Z")
# A reviewed environment keeps this placeholder where the server inserts the ``APP_KEY`` it
# generates once. The real key never reaches the controller or the review.
APP_KEY_PLACEHOLDER: Final = "{{generated}}"


def repository_locator(value: str) -> str:
    """The reviewed repository locator, or a ``ValueError`` naming why it is refused."""
    text = value.strip()
    if not text:
        raise ValueError("Enter the repository URL or SSH locator.")
    if len(text) > 512 or any(character.isspace() or ord(character) < 32 for character in text):
        raise ValueError("The repository locator contains unsupported characters.")
    if text.startswith("-"):
        raise ValueError("The repository locator may not start with a dash.")
    if text.startswith("https://"):
        if _HTTPS_USERINFO.match(text):
            raise ValueError("Remove the credentials from the repository URL.")
        if not _HTTPS_LOCATOR.fullmatch(text):
            raise ValueError("Enter a plain https:// repository URL without credentials.")
        return text
    if _SSH_LOCATOR.fullmatch(text):
        return text
    raise ValueError(
        "Enter a credential-free https:// URL or a user@host:path SSH locator. Other "
        "transports, credentials and Git options are not supported."
    )


def repository_ref(value: str) -> str:
    """The reviewed branch or tag, or a ``ValueError`` when Git must not be given it."""
    text = value.strip()
    if not text:
        raise ValueError("Enter a branch or tag.")
    if text == "@" or text.startswith("-"):
        raise ValueError("Enter a branch or tag, not a Git option.")
    if not _REF.fullmatch(text) or ".." in text or "@{" in text:
        raise ValueError("The branch or tag contains characters Git does not allow.")
    if text.startswith("/") or text.endswith(("/", ".")) or "//" in text:
        raise ValueError("The branch or tag is not a valid Git ref name.")
    if any(part.startswith(".") or part.endswith(".lock") for part in text.split("/")):
        raise ValueError("The branch or tag is not a valid Git ref name.")
    return text


def valid_fingerprint(value: str) -> bool:
    return bool(FINGERPRINT.fullmatch(value))


def render_environment(
    *,
    app_url: str,
    app_key: str,
    connection: str,
    host: str,
    port: str,
    database: str,
    username: str,
    socket: str = "",
) -> str:
    """Laravel's production environment, reviewed byte for byte.

    The keys and their non-production defaults are Laravel 13's own ``.env.example``
    (https://github.com/laravel/laravel/blob/13.x/.env.example); a Create Laravel site sets
    ``APP_ENV=production``, ``APP_DEBUG=false``, the site's ``APP_URL``, the socket database
    connection, ``LOG_CHANNEL=daily`` and ``LOG_DAILY_DAYS=14`` (Phase B #356).
    """
    if not app_url.startswith(("https://", "http://")):
        raise ValueError("A Laravel environment needs an absolute application URL.")
    if app_key != APP_KEY_PLACEHOLDER and not APP_KEY.fullmatch(app_key):
        raise ValueError("A Laravel environment needs a generated application key.")
    lines = [
        "APP_NAME=Laravel",
        "APP_ENV=production",
        f"APP_KEY={app_key}",
        "APP_DEBUG=false",
        f"APP_URL={app_url}",
        "",
        "APP_LOCALE=en",
        "APP_FALLBACK_LOCALE=en",
        "",
        "LOG_CHANNEL=daily",
        "LOG_DAILY_DAYS=14",
        "LOG_LEVEL=debug",
        "",
        f"DB_CONNECTION={connection}",
        f"DB_HOST={host}",
        f"DB_PORT={port}",
        f"DB_DATABASE={database}",
        f"DB_USERNAME={username}",
        "DB_PASSWORD=",
    ]
    if socket:
        lines.append(f"DB_SOCKET={socket}")
    lines += [
        "",
        "SESSION_DRIVER=database",
        "SESSION_LIFETIME=120",
        "",
        "CACHE_STORE=database",
        "QUEUE_CONNECTION=database",
        "",
    ]
    return "\n".join(lines)


# The maintenance gate: the site's Caddy file answering 503 for visitors while Caddy's
# automatic HTTPS challenge paths keep working (docs/target-architecture.md#laravel). The
# native body formats it, so it stays a reviewed, byte-stable string.
GATE_TEMPLATE: Final = MAINTENANCE_TEMPLATE
