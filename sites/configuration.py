"""Target site configuration. The native Caddy adapter owns its semantic round trip."""

import importlib.resources
from dataclasses import dataclass

from .names import readiness_directive, readiness_path, request

PHP_RUNTIMES = ("php84", "php85")


@dataclass(frozen=True)
class SiteSettings:
    """A supported site selection.

    ``https`` is the site's HTTPS setting: True for a site Caddy serves over bare host
    names with automatic HTTPS (docs/tls.md, ADR 0027), False for an HTTP-only site whose
    file uses explicit ``http://`` addresses. The product default is HTTPS.

    ``readiness`` is the path Barectl checks after a change (docs/sites.md#readiness). The
    non-default value is native evidence in the site's Caddy file, so a fresh controller
    reconstructs it without a Barectl marker.
    """

    identifier: str
    names: tuple[str, ...]
    runtime: str
    https: bool = True
    readiness: str = "/"

    def __post_init__(self) -> None:
        identifier, canonical = request(self.identifier, " ".join(self.names))
        canonical_readiness, problem = readiness_path(self.readiness)
        if (
            identifier != self.identifier
            or canonical != self.names
            or self.runtime not in PHP_RUNTIMES
            or problem
            or canonical_readiness != self.readiness
        ):
            raise ValueError("Not a supported site selection.")

    @property
    def account(self) -> str:
        return f"s{self.identifier}"

    @property
    def directory(self) -> str:
        return f"/var/www/{self.identifier}"

    @property
    def socket(self) -> str:
        return f"/run/php-fpm/sites/{self.identifier}/{self.runtime}/app.sock"

    @property
    def proxy_socket(self) -> str:
        return f"/run/haproxy/{self.identifier}/http.sock"

    @property
    def proxy(self) -> str:
        return f"p{self.identifier}"


POOL_TEMPLATE = importlib.resources.files("sites.bodies").joinpath("pool.conf").read_text()


CADDY_TEMPLATE = """{addresses} {{
{readiness}    root * {settings.directory}/current/public
    encode zstd gzip
    @hidden {{
        path_regexp hidden (^|/)\\.[^/]+
        not path /.well-known/*
    }}
    @wellknownhidden {{
        path_regexp wellknownhidden ^/\\.well-known/([^/]+/)*\\.[^/]+
    }}
    @config path_regexp config (?i)(^|/)wp-config\\.php(/|$)
    @uploads path_regexp uploads (?i)^/wp-content/uploads/.*\\.(php[0-9]*|phtml|phar)(/|$)
    @php path_regexp php \\.php(/|$)
    @index path /
    route {{
        respond @hidden 404
        respond @wellknownhidden 404
        respond @config 404
        respond @uploads 404
        rewrite @index /index.php
        reverse_proxy @php unix/{settings.proxy_socket}
        file_server
    }}
    log {{
        output file {settings.directory}/logs/access.json {{
            roll_size 20MiB
            roll_keep 5
            roll_keep_for 14d
        }}
        format filter {{
            wrap json
            fields {{
                request>uri query {{
                    replace key REDACTED
                    replace token REDACTED
                    replace signature REDACTED
                }}
            }}
        }}
    }}
}}
"""


def render_pool(settings: SiteSettings) -> str:
    return POOL_TEMPLATE.format(settings=settings)


def site_address(settings: SiteSettings, name: str) -> str:
    """One site address: a bare host for HTTPS, an explicit ``http://`` host otherwise."""
    return ("" if settings.https else "http://") + name


def render_caddy(settings: SiteSettings) -> str:
    addresses = ", ".join(site_address(settings, name) for name in settings.names)
    return CADDY_TEMPLATE.format(
        settings=settings,
        addresses=addresses,
        readiness=readiness_directive(settings.readiness),
    )


# A WordPress site's route: the front controller receives every path that is not a file, so
# pretty permalinks and application routes reach ``index.php``. WordPress's own public PHP
# is group-readable by Caddy so this check can see it. The original path travels in
# ``X-Forwarded-Uri`` because HAProxy's FastCGI application maps the rewritten path to the
# script while WordPress reads the original request URI (Phase B #380).
WORDPRESS_TEMPLATE = """{addresses} {{
    root * {settings.directory}/current/public
    encode zstd gzip
    @hidden {{
        path_regexp hidden (^|/)\\.[^/]+
        not path /.well-known/*
    }}
    @wellknownhidden {{
        path_regexp wellknownhidden ^/\\.well-known/([^/]+/)*\\.[^/]+
    }}
    @config path_regexp config (?i)(^|/)wp-config\\.php(/|$)
    @uploads path_regexp uploads (?i)^/wp-content/uploads/.*\\.(php[0-9]*|phtml|phar)(/|$)
    @php path_regexp php \\.php(/|$)
    @alias expression {{http.request.host}} != "{primary}"
    route {{
        respond @hidden 404
        respond @wellknownhidden 404
        respond @config 404
        respond @uploads 404
        redir @alias {scheme}://{primary}{{uri}} permanent
        vars original_uri {{http.request.uri}}
        try_files {{path}}index.php {{path}}/index.php {{path}} /index.php?{{query}}
        reverse_proxy @php unix/{settings.proxy_socket} {{
            header_up X-Forwarded-Uri {{vars.original_uri}}
        }}
        file_server
    }}
    log {{
        output file {settings.directory}/logs/access.json {{
            roll_size 20MiB
            roll_keep 5
            roll_keep_for 14d
        }}
        format filter {{
            wrap json
            fields {{
                request>uri query {{
                    replace key REDACTED
                    replace token REDACTED
                    replace signature REDACTED
                }}
            }}
        }}
    }}
}}
"""


def render_wordpress_caddy(settings: SiteSettings) -> str:
    addresses = ", ".join(site_address(settings, name) for name in settings.names)
    return WORDPRESS_TEMPLATE.format(
        settings=settings,
        addresses=addresses,
        primary=settings.names[0],
        scheme="https" if settings.https else "http",
    )


# A Laravel site's route: every path that is not a file reaches the front controller, so
# application routes and Laravel's ``/up`` health route work. The original path travels in
# ``X-Forwarded-Uri`` for the same reason as WordPress (Phase B #445). Laravel's private
# directories are denied explicitly even though they sit outside the public root, so a
# future layout change cannot expose them.
LARAVEL_TEMPLATE = """{addresses} {{
    root * {settings.directory}/current/public
    encode zstd gzip
    @hidden {{
        path_regexp hidden (^|/)\\.[^/]+
        not path /.well-known/*
    }}
    @wellknownhidden {{
        path_regexp wellknownhidden ^/\\.well-known/([^/]+/)*\\.[^/]+
    }}
    @private path /storage/* /vendor/* /bootstrap/cache/*
    @config path_regexp config (?i)(^|/)\\.env(/|$)
    @php path_regexp php \\.php(/|$)
    @index path /
    @alias expression {{http.request.host}} != "{primary}"
    route {{
        respond @hidden 404
        respond @wellknownhidden 404
        respond @private 404
        respond @config 404
        redir @alias {scheme}://{primary}{{uri}} permanent
        vars original_uri {{http.request.uri}}
        rewrite @index /index.php
        try_files {{path}}index.php {{path}}/index.php {{path}} /index.php?{{query}}
        reverse_proxy @php unix/{settings.proxy_socket} {{
            header_up X-Forwarded-Uri {{vars.original_uri}}
        }}
        file_server
    }}
    log {{
        output file {settings.directory}/logs/access.json {{
            roll_size 20MiB
            roll_keep 5
            roll_keep_for 14d
        }}
        format filter {{
            wrap json
            fields {{
                request>uri query {{
                    replace key REDACTED
                    replace token REDACTED
                    replace signature REDACTED
                }}
            }}
        }}
    }}
}}
"""


def render_laravel_caddy(settings: SiteSettings) -> str:
    addresses = ", ".join(site_address(settings, name) for name in settings.names)
    return LARAVEL_TEMPLATE.format(
        settings=settings,
        addresses=addresses,
        primary=settings.names[0],
        scheme="https" if settings.https else "http",
    )


# A site's maintenance form: visitors get 503 while Caddy's automatic HTTPS challenge path
# keeps answering through the site's private admission socket. The API is shared by Laravel
# Deploy and Create WordPress site (docs/target-architecture.md).
MAINTENANCE_TEMPLATE = """{addresses} {{
    @acme path /.well-known/acme-challenge/*
    handle @acme {{
        reverse_proxy unix/{settings.proxy_socket}
    }}
    @hidden {{
        path_regexp hidden (^|/)\\.[^/]+
        not path /.well-known/*
    }}
    route {{
        respond @hidden 404
        respond 503
    }}
    log {{
        output file {settings.directory}/logs/access.json {{
            roll_size 20MiB
            roll_keep 5
            roll_keep_for 14d
        }}
    }}
}}
"""


def render_maintenance(settings: SiteSettings) -> str:
    addresses = ", ".join(site_address(settings, name) for name in settings.names)
    return MAINTENANCE_TEMPLATE.format(settings=settings, addresses=addresses)
