"""Target site configuration. The native Caddy adapter owns its semantic round trip."""

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


def render_pool(settings: SiteSettings) -> str:
    return f"""[{settings.identifier}]
user = {settings.account}
group = {settings.account}
listen = {settings.socket}
listen.owner = {settings.account}
listen.group = caddy
listen.mode = 0660
pm = ondemand
pm.max_children = 2
pm.process_idle_timeout = 10s
clear_env = yes
security.limit_extensions = .php
request_slowlog_timeout = 5s
slowlog = {settings.directory}/logs/php-slow.log
php_admin_flag[log_errors] = on
php_admin_value[error_log] = {settings.directory}/logs/php-error.log
php_admin_value[session.save_path] = {settings.directory}/private/sessions
php_admin_value[upload_tmp_dir] = {settings.directory}/private/tmp
php_admin_value[sys_temp_dir] = {settings.directory}/private/tmp
"""


def render_caddy(settings: SiteSettings) -> str:
    addresses = ", ".join("http://" + name for name in settings.names)
    return f"""{addresses} {{
    root * {settings.directory}/current/public
    encode zstd gzip
    @hidden {{
        path_regexp hidden (^|/)\\.[^/]+
        not path /.well-known/*
    }}
    @wellknownhidden {{
        path_regexp wellknownhidden ^/\\.well-known/.*(^|/)\\.[^/]+
    }}
    @config path_regexp config (?i)(^|/)wp-config\\.php(/|$)
    @uploads path_regexp uploads (?i)^/wp-content/uploads/.*\\.(php[0-9]*|phtml|phar)(/|$)
    route {{
        respond @hidden 404
        respond @wellknownhidden 404
        respond @config 404
        respond @uploads 404
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


def settings_from_adapted(identifier: str, value: object) -> SiteSettings:
    """Extract candidate settings. Recognition still requires complete native round trip."""
    hosts: list[tuple[str, ...]] = []
    roots: set[str] = set()
    sockets: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if (
                    key == "host"
                    and isinstance(child, list)
                    and all(isinstance(x, str) for x in child)
                ):
                    hosts.append(tuple(child))
                elif key == "root" and isinstance(child, str):
                    roots.add(child)
                elif key == "dial" and isinstance(child, str):
                    sockets.add(child)
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    if len(hosts) != 1 or roots != {f"/var/www/{identifier}/current/public"} or len(sockets) != 1:
        raise ValueError("The adapted site does not identify one supported route.")
    socket = sockets.pop()
    runtime = next(
        (
            entry
            for entry in PHP_RUNTIMES
            if socket == f"unix//run/php-fpm/{entry}/{identifier}.sock"
        ),
        "",
    )
    return SiteSettings(identifier, hosts[0], runtime)
