"""Target site configuration. The native Caddy adapter owns its semantic round trip."""

import importlib.resources
from dataclasses import dataclass

from .names import request

PHP_RUNTIMES = ("php84", "php85")


@dataclass(frozen=True)
class SiteSettings:
    identifier: str
    names: tuple[str, ...]
    runtime: str

    def __post_init__(self) -> None:
        identifier, canonical = request(self.identifier, " ".join(self.names), max_name_octets=253)
        if (
            identifier != self.identifier
            or canonical != self.names
            or self.runtime not in PHP_RUNTIMES
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
        return f"/run/php-fpm/{self.runtime}/{self.identifier}.sock"


POOL_TEMPLATE = importlib.resources.files("sites.bodies").joinpath("pool.conf").read_text()


CADDY_TEMPLATE = """{addresses} {{
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
    @index path /
    route {{
        respond @hidden 404
        respond @wellknownhidden 404
        respond @config 404
        respond @uploads 404
        rewrite @index /index.php
        php_fastcgi unix/{settings.socket}
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


def render_caddy(settings: SiteSettings) -> str:
    addresses = ", ".join("http://" + name for name in settings.names)
    return CADDY_TEMPLATE.format(settings=settings, addresses=addresses)
