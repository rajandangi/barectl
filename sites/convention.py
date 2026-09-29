"""The files Barectl generates for a site (docs/site-conventions.md).

Recognition re-renders a file from the values it declares and requires byte equality, so
only the exact templates of released convention revisions are admitted; discovery reads the
same files with its general parser.
"""

import re
from dataclasses import dataclass

from .names import IDENTIFIER, canonical_name

CONVENTION_REVISION = 1
WEB_ROOT = "/var/www"
SITES_AVAILABLE = "/etc/nginx/sites-available"
SITES_ENABLED = "/etc/nginx/sites-enabled"
SOCKET_DIRECTORY = "/run/php"
WEB_USER = "www-data"
NOLOGIN = "/usr/sbin/nologin"
PROBE_TOKEN = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True)
class SitePaths:
    """Where the convention places one site's resources on the default PHP version."""

    identifier: str
    php: str

    def __post_init__(self) -> None:
        if not IDENTIFIER.fullmatch(self.identifier) or not re.fullmatch(r"8\.[0-9]", self.php):
            raise ValueError("Not a valid site identifier or PHP version.")

    @property
    def user(self) -> str:
        return f"s{self.identifier}"

    @property
    def source(self) -> str:
        return f"{SITES_AVAILABLE}/{self.identifier}.conf"

    @property
    def link(self) -> str:
        return f"{SITES_ENABLED}/{self.identifier}.conf"

    @property
    def pool_directory(self) -> str:
        return f"/etc/php/{self.php}/fpm/pool.d"

    @property
    def pool(self) -> str:
        return f"{self.pool_directory}/{self.identifier}.conf"

    @property
    def socket(self) -> str:
        return f"{SOCKET_DIRECTORY}/{self.user}.sock"

    @property
    def boundary(self) -> str:
        return f"{WEB_ROOT}/{self.identifier}"

    @property
    def public(self) -> str:
        return f"{self.boundary}/public"

    @property
    def private(self) -> str:
        return f"{self.boundary}/private"

    @property
    def placeholder(self) -> str:
        return f"{self.public}/index.html"

    def probe(self, token: str) -> str:
        if not PROBE_TOKEN.fullmatch(token):
            raise ValueError("Not a valid probe token.")
        return f"{self.public}/probe-{token}.php"

    @property
    def certificates(self) -> tuple[str, ...]:
        """The TLS convention's later paths for this identifier (docs/site-conventions.md)."""
        return (
            f"/var/lib/letsencrypt/{self.identifier}",
            f"/etc/letsencrypt/live/{self.identifier}",
            f"/etc/letsencrypt/archive/{self.identifier}",
            f"/etc/letsencrypt/renewal/{self.identifier}.conf",
        )

    @property
    def fpm_service(self) -> str:
        return f"php{self.php}-fpm.service"


def _checked(identifier: str) -> str:
    if not IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a valid site identifier.")
    return identifier


def render_site(identifier: str, names: tuple[str, ...], *, ipv6: bool) -> str:
    """docs/site-conventions.md#supported-configuration-grammar"""
    identifier = _checked(identifier)
    ipv6_listen = "\tlisten [::]:80;\n" if ipv6 else ""
    return (
        "server {\n"
        "\tlisten 80;\n"
        f"{ipv6_listen}"
        f"\tserver_name {' '.join(names)};\n"
        f"\troot {WEB_ROOT}/{identifier}/public;\n"
        "\tindex index.php index.html;\n"
        "\tautoindex off;\n"
        "\n"
        "\tlocation / {\n"
        "\t\ttry_files $uri $uri/ =404;\n"
        "\t}\n"
        "\n"
        "\tlocation ~ /\\. {\n"
        "\t\tdeny all;\n"
        "\t}\n"
        "\n"
        "\tlocation ~ \\.php$ {\n"
        "\t\ttry_files $uri =404;\n"
        "\t\tinclude fastcgi.conf;\n"
        '\t\tfastcgi_param HTTP_PROXY "";\n'
        f"\t\tfastcgi_pass unix:{SOCKET_DIRECTORY}/s{identifier}.sock;\n"
        "\t}\n"
        "}\n"
    )


def render_pool(identifier: str) -> str:
    user = f"s{_checked(identifier)}"
    return (
        f"[{identifier}]\n"
        f"user = {user}\n"
        f"group = {user}\n"
        f"listen = {SOCKET_DIRECTORY}/{user}.sock\n"
        f"listen.owner = {WEB_USER}\n"
        f"listen.group = {WEB_USER}\n"
        "listen.mode = 0600\n"
        "pm = ondemand\n"
        "pm.max_children = 5\n"
        "pm.process_idle_timeout = 10s\n"
        "clear_env = yes\n"
        "security.limit_extensions = .php\n"
    )


def render_placeholder(identifier: str) -> str:
    identifier = _checked(identifier)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        f'<head><meta charset="utf-8"><title>{identifier}</title></head>\n'
        f"<body><p>Site {identifier} is ready.</p></body>\n"
        "</html>\n"
    )


def render_probe(token: str) -> str:
    if not PROBE_TOKEN.fullmatch(token):
        raise ValueError("Not a valid probe token.")
    return (
        f'<?php\necho "barectl-probe {token} " . posix_geteuid() . " " . posix_getegid() . "\\n";\n'
    )


def probe_marker(token: str) -> str:
    """What the probe prints before the PHP identity, up to the numeric IDs."""
    return f"barectl-probe {token} "


@dataclass(frozen=True)
class RecognizedSite:
    identifier: str
    names: tuple[str, ...]
    ipv6: bool


_SERVER_NAME = re.compile(r"^\tserver_name ([a-z0-9. -]{1,600});$", re.MULTILINE)


def recognize_site(identifier: str, text: str) -> RecognizedSite | None:
    """The site ``text`` declares when it is exactly a convention site file for
    ``identifier``; ``None`` for anything else."""
    if not IDENTIFIER.fullmatch(identifier):
        return None
    found = _SERVER_NAME.search(text)
    if found is None:
        return None
    names = tuple(found[1].split(" "))
    canonical = tuple(canonical_name(name)[0] for name in names)
    if canonical != names or not 1 <= len(names) <= 10 or len(set(names)) != len(names):
        return None
    for ipv6 in (True, False):
        if text == render_site(identifier, names, ipv6=ipv6):
            return RecognizedSite(identifier, names, ipv6)
    return None


def recognize_pool(identifier: str, text: str) -> bool:
    return IDENTIFIER.fullmatch(identifier) is not None and text == render_pool(identifier)
