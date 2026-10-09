"""The files Barectl generates for a site (docs/site-conventions.md).

Recognition re-renders a file from the values it declares and requires byte equality, so
only the exact templates of released convention revisions are admitted; discovery reads the
same files with its general parser.
"""

import itertools
import re
from dataclasses import dataclass
from enum import StrEnum

from bootstrap.php_supply import ELIGIBLE_BRANCHES
from discovery.observations.configuration import (
    PHP_BASE_DIR,
    POOL_SUBPATH,
    SITES_AVAILABLE_DIR,
    SITES_ENABLED_DIR,
)
from discovery.observations.sites import (
    CHALLENGE_ROOT,
    CONF_D_DIR,
    NOLOGIN,
    TLS_DEFAULT_PATH,
    WEB_ROOT,
    WEB_USER,
    SiteLayout,
    is_tls_default,
    render_tls_default,
)

from .names import IDENTIFIER, canonical_name

CONVENTION_REVISION = 4
LEGACY_REVISION = 3
SITES_AVAILABLE = SITES_AVAILABLE_DIR
SITES_ENABLED = SITES_ENABLED_DIR
PROBE_TOKEN = re.compile(r"[0-9a-f]{32}")
# docs/site-conventions.md#site-identity-and-layout: recovery preimages of replaced files.
BACKUP_DIRECTORY = "/var/backups/nginx"
_UNIT_HEX = re.compile(r"[0-9a-f]{32}")
__all__ = [
    "CHALLENGE_ROOT",
    "CONF_D_DIR",
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


class Application(StrEnum):
    """docs/site-conventions.md#wordpress-forms: the application a site file routes."""

    # The generic PHP forms.
    PHP = "php"
    # WordPress behind the provisioning gate, which serves 503 for application paths.
    WORDPRESS_GATE = "wordpress_gate"
    WORDPRESS = "wordpress"

    @property
    def wordpress(self) -> bool:
        return self is not Application.PHP


@dataclass(frozen=True)
class SitePaths(SiteLayout):
    """Where the convention places one site's resources, as discovery locates them, and the
    paths only creating a site needs."""

    def __post_init__(self) -> None:
        if not IDENTIFIER.fullmatch(self.identifier) or not re.fullmatch(r"8\.[0-9]", self.version):
            raise ValueError("Not a valid site identifier or PHP version.")
        if self.revision not in (LEGACY_REVISION, CONVENTION_REVISION):
            raise ValueError("Not a supported site convention revision.")
        if self.revision == CONVENTION_REVISION and self.version not in ELIGIBLE_BRANCHES:
            raise ValueError("Not an eligible selected PHP branch.")

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
    identifier: str,
    names: tuple[str, ...],
    *,
    ipv6: bool,
    stage: Stage = Stage.HTTP,
    php_version: str = "",
    application: Application = Application.PHP,
    canonical: str = "",
) -> str:
    """docs/site-conventions.md#supported-configuration-grammar

    ``canonical`` is the name HTTP and alias requests are redirected to; it defaults to the
    first name, which the generic forms always use.
    """
    identifier = _checked(identifier)
    canonical = canonical or names[0]
    if canonical not in names or (not application.wordpress and canonical != names[0]):
        raise ValueError("Not a canonical name of the site.")
    if application.wordpress and stage not in {Stage.HTTPS, Stage.REDIRECT}:
        raise ValueError("WordPress is routed only by the HTTPS forms.")
    socket = SitePaths(
        identifier,
        php_version or "8.0",
        revision=CONVENTION_REVISION if php_version else LEGACY_REVISION,
    ).socket
    locations = _application_locations(application, socket)
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
            f"\t\treturn 301 https://{canonical}$request_uri;\n"
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
            f"{locations}"
            "}\n"
        )
    if not stage.activated:
        return http
    lineage = (
        f"\tssl_certificate /etc/letsencrypt/live/{identifier}/fullchain.pem;\n"
        f"\tssl_certificate_key /etc/letsencrypt/live/{identifier}/privkey.pem;\n"
    )
    served = (canonical,) if application.wordpress else names
    https = (
        "server {\n"
        "\tlisten 443 ssl;\n"
        f"{ipv6_https}"
        f"\tserver_name {' '.join(served)};\n"
        f"\troot {WEB_ROOT}/{identifier}/public;\n"
        "\tindex index.php index.html;\n"
        "\tautoindex off;\n"
        f"{lineage}"
        "\n"
        f"{locations}"
        "}\n"
    )
    aliases = tuple(name for name in names if name != canonical) if application.wordpress else ()
    if aliases:
        https += (
            "\nserver {\n"
            "\tlisten 443 ssl;\n"
            f"{ipv6_https}"
            f"\tserver_name {' '.join(aliases)};\n"
            f"{lineage}"
            "\n"
            "\tlocation / {\n"
            f"\t\treturn 301 https://{canonical}$request_uri;\n"
            "\t}\n"
            "}\n"
        )
    return http + "\n" + https


def _application_locations(application: Application, socket: str) -> str:
    """The locations that serve the site's application, after the challenge route."""
    php = (
        "\tlocation ~ \\.php$ {\n"
        "\t\ttry_files $uri =404;\n"
        "\t\tinclude fastcgi.conf;\n"
        '\t\tfastcgi_param HTTP_PROXY "";\n'
        f"\t\tfastcgi_pass unix:{socket};\n"
        "\t}\n"
    )
    dotfiles = "\tlocation ~ /\\. {\n\t\tdeny all;\n\t}\n\n"
    if application is Application.WORDPRESS_GATE:
        return (
            "\tlocation = /wp-admin/install.php {\n\t\treturn 503;\n\t}\n"
            "\n"
            # The socket stays so the selected branch survives the gate.
            "\tlocation ~ \\.php$ {\n"
            f"\t\tfastcgi_pass unix:{socket};\n"
            "\t\treturn 503;\n"
            "\t}\n"
            "\n"
            "\tlocation / {\n\t\treturn 503;\n\t}\n"
        )
    if application is Application.WORDPRESS:
        return (
            "\tlocation = /wp-config.php {\n\t\tdeny all;\n\t}\n"
            "\n"
            "\tlocation ~* ^/wp-content/uploads/.*\\.(?:php[0-9]?|phtml|phar|pht|phps)(?:$|/) {\n"
            "\t\tdeny all;\n"
            "\t}\n"
            "\n"
            "\tlocation / {\n\t\ttry_files $uri $uri/ /index.php?$args;\n\t}\n"
            "\n"
            f"{dotfiles}{php}"
        )
    return f"\tlocation / {{\n\t\ttry_files $uri $uri/ =404;\n\t}}\n\n{dotfiles}{php}"


def render_pool(identifier: str, *, php_version: str = "") -> str:
    """The pool file; its fixed settings are the ones discovery requires, in order."""
    layout = SitePaths(
        _checked(identifier),
        php_version or "8.0",
        revision=CONVENTION_REVISION if php_version else LEGACY_REVISION,
    )
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
    php_version: str = ""
    revision: int = LEGACY_REVISION
    application: Application = Application.PHP
    # Empty for the generic forms, which always redirect to the first name.
    canonical: str = ""

    @property
    def canonical_name(self) -> str:
        return self.canonical or self.names[0]


_CANONICAL = re.compile(r"^\t\treturn 301 https://([a-z0-9.-]{1,46})\$request_uri;$", re.MULTILINE)
_SERVER_NAME = re.compile(r"^\tserver_name ([a-z0-9. -]{1,600});$", re.MULTILINE)


def declared_php_version(identifier: str, text: str) -> str | None:
    sockets = re.findall(r"^\t\tfastcgi_pass unix:([^;]+);$", text, re.MULTILINE)
    versions = ["", *ELIGIBLE_BRANCHES]
    for version in versions:
        suffix = f"-php{version}" if version else ""
        if sockets and set(sockets) == {f"/run/php/s{identifier}{suffix}.sock"}:
            return version
    return None


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
    return _recognized_form(identifier, names, text)


def _recognized_form(identifier: str, names: tuple[str, ...], text: str) -> RecognizedSite | None:
    declared = _CANONICAL.search(text)
    for application in Application:
        if application.wordpress != _wordpress_marked(text):
            continue
        stages = (Stage.HTTPS, Stage.REDIRECT) if application.wordpress else tuple(Stage)
        # Only the redirect forms declare a canonical name other than the first.
        canonicals = [names[0]]
        if declared and application.wordpress and declared[1] in names:
            canonicals.append(declared[1])
        for stage, canonical, ipv6, php_version in itertools.product(
            stages, dict.fromkeys(canonicals), (True, False), ("", *ELIGIBLE_BRANCHES)
        ):
            if text == render_site(
                identifier,
                names,
                ipv6=ipv6,
                stage=stage,
                php_version=php_version,
                application=application,
                canonical=canonical,
            ):
                return RecognizedSite(
                    identifier,
                    names,
                    ipv6,
                    stage,
                    php_version,
                    CONVENTION_REVISION if php_version else LEGACY_REVISION,
                    application,
                    canonical if application.wordpress else "",
                )
    return None


def _wordpress_marked(text: str) -> bool:
    return "/wp-admin/install.php" in text or "/wp-config.php" in text


def recognize_pool(identifier: str, text: str, *, php_version: str = "") -> bool:
    return IDENTIFIER.fullmatch(identifier) is not None and text == render_pool(
        identifier, php_version=php_version
    )
