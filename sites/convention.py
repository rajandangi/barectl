"""The files Barectl generates for a site (docs/site-conventions.md).

Recognition re-renders a file from the values it declares and requires byte equality, so
only the exact templates of released convention revisions are admitted; discovery reads the
same files with its general parser.
"""

import re
from dataclasses import dataclass
from enum import StrEnum

from discovery.observations.configuration import PHP_BASE_DIR, POOL_SUBPATH, SITES_ENABLED_DIR
from discovery.observations.sites import (
    CHALLENGE_ROOT,
    CONF_D_DIR,
    NOLOGIN,
    SITES_AVAILABLE_DIR,
    SOCKET_DIR,
    TLS_DEFAULT_PATH,
    WEB_ROOT,
    WEB_USER,
    SiteLayout,
    is_tls_default,
    render_tls_default,
)

from .names import IDENTIFIER, canonical_name

CONVENTION_REVISION = 3
SITES_AVAILABLE = SITES_AVAILABLE_DIR
TLS_CONF_DIRECTORY = CONF_D_DIR
SITES_ENABLED = SITES_ENABLED_DIR
PROBE_TOKEN = re.compile(r"[0-9a-f]{32}")
# docs/site-conventions.md#site-identity-and-layout: recovery preimages of replaced files.
BACKUP_DIRECTORY = "/var/backups/nginx"
_UNIT_HEX = re.compile(r"[0-9a-f]{32}")
__all__ = [
    "CHALLENGE_ROOT",
    "NOLOGIN",
    "TLS_DEFAULT_PATH",
    "WEB_ROOT",
    "WEB_USER",
    "is_tls_default",
    "render_tls_default",
]


class Stage(StrEnum):
    """docs/site-conventions.md#tls-convention: the site file's released forms."""

    HTTP = "http"
    # HTTP with the HTTP-01 challenge location.
    CHALLENGE = "challenge"
    # HTTP with the challenge location and an HTTPS server block.
    HTTPS = "https"
    # The challenge location and an HTTP redirect to the canonical HTTPS name, with the
    # HTTPS server block.
    REDIRECT = "redirect"

    @property
    def routes_challenges(self) -> bool:
        """Whether the form keeps serving the HTTP-01 challenge location."""
        return self in {Stage.CHALLENGE, Stage.HTTPS, Stage.REDIRECT}

    @property
    def activated(self) -> bool:
        """Whether the form references the site's certificate lineage over HTTPS."""
        return self in {Stage.HTTPS, Stage.REDIRECT}


@dataclass(frozen=True)
class SitePaths(SiteLayout):
    """Where the convention places one site's resources, as discovery locates them, and the
    paths only creating a site needs."""

    def __post_init__(self) -> None:
        if not IDENTIFIER.fullmatch(self.identifier) or not re.fullmatch(r"8\.[0-9]", self.version):
            raise ValueError("Not a valid site identifier or PHP version.")

    @property
    def php(self) -> str:
        return self.version

    @property
    def link(self) -> str:
        return self.enabled

    @property
    def pool_directory(self) -> str:
        return f"{PHP_BASE_DIR}/{self.version}/{POOL_SUBPATH}"

    @property
    def placeholder(self) -> str:
        return f"{self.public}/index.html"

    def probe(self, token: str) -> str:
        if not PROBE_TOKEN.fullmatch(token):
            raise ValueError("Not a valid probe token.")
        return f"{self.public}/probe-{token}.php"

    @property
    def challenge_parents(self) -> tuple[str, ...]:
        """The directories above the webroot and the recovery preimage."""
        return ("/var/lib", CHALLENGE_ROOT, "/var/backups", BACKUP_DIRECTORY)

    def backup(self, unit_hex: str) -> str:
        """The recovery preimage of the site file that the run ``unit_hex`` replaces."""
        if not _UNIT_HEX.fullmatch(unit_hex):
            raise ValueError("Not a valid unit suffix.")
        return f"{BACKUP_DIRECTORY}/{self.identifier}.conf.{unit_hex}"

    def challenge_probe(self, token: str) -> str:
        if not PROBE_TOKEN.fullmatch(token):
            raise ValueError("Not a valid probe token.")
        return f"{self.webroot}/.well-known/acme-challenge/barectl-{token}"

    @property
    def certificates(self) -> tuple[str, ...]:
        """The TLS convention's later paths for this identifier (docs/site-conventions.md)."""
        return (
            self.webroot,
            f"/etc/letsencrypt/live/{self.identifier}",
            f"/etc/letsencrypt/archive/{self.identifier}",
            f"/etc/letsencrypt/renewal/{self.identifier}.conf",
        )

    @property
    def fpm_service(self) -> str:
        return f"php{self.version}-fpm.service"


def _checked(identifier: str) -> str:
    if not IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a valid site identifier.")
    return identifier


def render_site(
    identifier: str, names: tuple[str, ...], *, ipv6: bool, stage: Stage = Stage.HTTP
) -> str:
    """docs/site-conventions.md#supported-configuration-grammar"""
    identifier = _checked(identifier)
    ipv6_http = "\tlisten [::]:80;\n" if ipv6 else ""
    ipv6_https = "\tlisten [::]:443 ssl;\n" if ipv6 else ""
    challenge = (
        (
            "\tlocation ^~ /.well-known/acme-challenge/ {\n"
            f"\t\troot {CHALLENGE_ROOT}/{identifier};\n"
            "\t\ttry_files $uri =404;\n"
            "\t}\n"
            "\n"
        )
        if stage.routes_challenges
        else ""
    )
    if stage == Stage.REDIRECT:
        http = (
            "server {\n"
            "\tlisten 80;\n"
            f"{ipv6_http}"
            f"\tserver_name {' '.join(names)};\n"
            "\n"
            f"{challenge}"
            "\tlocation / {\n"
            f"\t\treturn 301 https://{names[0]}$request_uri;\n"
            "\t}\n"
            "}\n"
        )
    else:
        http = (
            "server {\n"
            "\tlisten 80;\n"
            f"{ipv6_http}"
            f"\tserver_name {' '.join(names)};\n"
            f"\troot {WEB_ROOT}/{identifier}/public;\n"
            "\tindex index.php index.html;\n"
            "\tautoindex off;\n"
            "\n"
            f"{challenge}"
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
            f"\t\tfastcgi_pass unix:{SOCKET_DIR}/s{identifier}.sock;\n"
            "\t}\n"
            "}\n"
        )
    if not stage.activated:
        return http
    https = (
        "server {\n"
        "\tlisten 443 ssl;\n"
        f"{ipv6_https}"
        f"\tserver_name {' '.join(names)};\n"
        f"\troot {WEB_ROOT}/{identifier}/public;\n"
        "\tindex index.php index.html;\n"
        "\tautoindex off;\n"
        f"\tssl_certificate /etc/letsencrypt/live/{identifier}/fullchain.pem;\n"
        f"\tssl_certificate_key /etc/letsencrypt/live/{identifier}/privkey.pem;\n"
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
        f"\t\tfastcgi_pass unix:{SOCKET_DIR}/s{identifier}.sock;\n"
        "\t}\n"
        "}\n"
    )
    return http + "\n" + https


def render_pool(identifier: str) -> str:
    """The pool file; its fixed settings are the ones discovery requires, in order."""
    layout = SiteLayout(_checked(identifier), "8.0")
    settings = layout.pool_settings().items()
    return f"[{identifier}]\n" + "".join(f"{key} = {value}\n" for key, value in settings)


def render_placeholder(identifier: str) -> str:
    identifier = _checked(identifier)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        f'<head><meta charset="utf-8"><title>{identifier}</title></head>\n'
        f"<body><p>{ready(identifier)}</p></body>\n"
        "</html>\n"
    )


def ready(identifier: str) -> str:
    """The placeholder's text, which serving checks look for; unique to the site."""
    return f"Site {_checked(identifier)} is ready."


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
    stage: Stage = Stage.HTTP


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
    canonical = [canonical_name(name) for name in names]
    if (
        any(
            problem or value != name
            for (value, problem), name in zip(canonical, names, strict=True)
        )
        or not 1 <= len(names) <= 10
        or len(set(names)) != len(names)
    ):
        return None
    for stage in Stage:
        for ipv6 in (True, False):
            if text == render_site(identifier, names, ipv6=ipv6, stage=stage):
                return RecognizedSite(identifier, names, ipv6, stage)
    return None


def recognize_pool(identifier: str, text: str) -> bool:
    return IDENTIFIER.fullmatch(identifier) is not None and text == render_pool(identifier)
