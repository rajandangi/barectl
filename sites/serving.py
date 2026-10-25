"""Immutable per-site admission and independent PHP service configuration (ADR 0038)."""

from pathlib import PurePosixPath
from types import SimpleNamespace

from .configuration import SiteSettings

HAPROXY_UNIT = """[Unit]
Description=Private HTTP to FastCGI admission for %i
After=network.target

[Service]
Slice=system.slice
Type=simple
ExecStart=/nix/var/nix/profiles/barectl/haproxy/bin/haproxy -f /etc/haproxy/sites/%i.cfg
RuntimeDirectory=haproxy/%i
RuntimeDirectoryMode=0755
PrivateDevices=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
RestrictAddressFamilies=AF_UNIX
Restart=on-failure
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def fpm_unit(entry: str) -> str:
    if entry not in ("php84", "php85"):
        raise ValueError("Unknown PHP runtime.")
    config = f"/etc/php-fpm/sites/%i/{entry}"
    runtime = f"/run/php-fpm/sites/%i/{entry}"
    executable = f"/nix/var/nix/profiles/barectl/{entry}/bin/php-fpm"
    return f"""[Unit]
Description=Independent {entry} PHP service for %i
After=network.target

[Service]
Slice=system.slice
Type=notify
ExecStartPre=/usr/bin/install -d -m 0700 {runtime}/status {runtime}/diagnostic
ExecStartPost=/usr/bin/chmod 0600 {runtime}/status/listen.sock
ExecStart={executable} -F -y {config}/php-fpm.conf -c {config}/php.ini
RuntimeDirectory=php-fpm/sites/%i/{entry}
RuntimeDirectoryMode=0755
KillSignal=SIGQUIT
TimeoutStopSec=310s
PrivateDevices=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
Restart=on-failure
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def haproxy_config(settings: SiteSettings | SimpleNamespace) -> str:
    site = settings.identifier
    return f"""global
    maxconn 64
    user p{site}
    group p{site}
    nbthread 1
    tune.quic.fe.sock-per-conn force-off
    tune.quic.fe.tx.udp-gso off
    tune.quic.be.tx.udp-gso off
    server-state-file /var/lib/haproxy/sites/{site}.state
    stats socket /run/haproxy/{site}/admin.sock uid 0 gid 0 mode 600 level admin
    log /dev/log local0
    log-tag haproxy-site-{site}
defaults
    mode http
    timeout connect 0
    timeout client 0
    timeout server 0
    timeout queue 0
    retry-on conn-failure
    retries 2
fcgi-app php
    docroot /var/www/{site}/current/public
    index index.php
    path-info ^(/.+?\\.php)(/.*)?$
    set-param HTTP_X_FORWARDED_URI %[req.hdr(X-Forwarded-Uri)]
    set-param HTTPS %[var(txn.https)]
    set-param SERVER_PORT %[dst_port]
    no option keep-conn
backend php
    use-fcgi-app php
    balance roundrobin
    load-server-state-from-file global
    option redispatch
    server php84 /run/php-fpm/sites/{site}/php84/app.sock proto fcgi id 1 maxconn 2 disabled
    server php85 /run/php-fpm/sites/{site}/php85/app.sock proto fcgi id 2 maxconn 2 disabled
frontend incoming
    bind /run/haproxy/{site}/http.sock user caddy group caddy mode 600
    http-request del-header Proxy
    http-request set-var(txn.https) str(on) if {{ req.hdr(X-Forwarded-Proto) -i https }}
    http-request set-var(txn.https) str(off) unless {{ var(txn.https) -m found }}
    default_backend php
"""


def php_directory(identifier: str, runtime: str) -> str:
    return f"/etc/php-fpm/sites/{identifier}/{runtime}"


def site_pool_path(identifier: str, runtime: str) -> str:
    return f"{php_directory(identifier, runtime)}/pools/{identifier}.conf"


def master_config(settings: SiteSettings | SimpleNamespace) -> str:
    # docs/site-conventions.md: a stop or restart waits for running requests.
    return (
        "[global]\ndaemonize = no\nerror_log = syslog\nprocess_control_timeout = 300s\n"
        f"include = {php_directory(settings.identifier, settings.runtime)}/pools/*.conf\n"
    )


def diagnostic_pool(settings: SiteSettings | SimpleNamespace, extension: str = "") -> str:
    private = f"/var/lib/php-fpm/sites/{settings.identifier}/{settings.runtime}/diagnostic"
    temporary = PurePosixPath(private) / "tmp"
    client = f"php_admin_value[extension] = {extension}\n" if extension else ""
    return f"""[diagnostic]
user = php-probe
group = php-probe
listen = /run/php-fpm/sites/{settings.identifier}/{settings.runtime}/diagnostic/listen.sock
listen.owner = root
listen.group = root
listen.mode = 0600
pm = static
pm.max_children = 1
clear_env = yes
security.limit_extensions = .php
php_admin_value[session.save_path] = {private}/session
php_admin_value[upload_tmp_dir] = {private}/upload
php_admin_value[sys_temp_dir] = {temporary}
{client}"""


def service_units() -> dict[str, str]:
    return {
        "/etc/systemd/system/haproxy-site@.service": HAPROXY_UNIT,
        **{
            f"/etc/systemd/system/php-fpm-site-{entry}@.service": fpm_unit(entry)
            for entry in ("php84", "php85")
        },
    }
