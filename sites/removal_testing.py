"""Removal evidence shared by the fast page tests and the browser journeys."""

from bootstrap.standing import Standing
from databases import binding, provision
from operations.engine import ReviewDraft
from operations.fakes import BOOT_ID
from operations.inputs import PreparationInputs
from sites import remove

PATHS = (
    "/etc/caddy/sites/alpha.caddy",
    "/etc/haproxy/sites/alpha.cfg",
    "/var/lib/haproxy/sites/alpha.state",
    "/run/haproxy/alpha",
    "/etc/php-fpm/sites/alpha",
    "/var/lib/php-fpm/sites/alpha",
    "/run/php-fpm/sites/alpha",
    "/var/www/alpha",
    "/etc/valkey/alpha.conf",
    "/var/lib/valkey/alpha",
    "/run/valkey/alpha",
    "/etc/systemd/system/valkey-server@alpha.service.d",
)
DIGEST = "a" * 64


def evidence(
    *,
    names: tuple[str, ...] = ("alpha.example.com",),
    present: bool = True,
    binding_state: str = "satisfied",
) -> remove.RemovalEvidence:
    current = (
        binding.Binding("mariadb", "alpha", binding_state, ("principal", "database", "privileges"))
        if binding_state
        else None
    )
    database = provision.DatabaseEvidence(
        "mariadb" if binding_state else "",
        "MariaDB" if binding_state else "the database engine",
        bool(binding_state),
        (),
        current,
        "",
        "principal\t1\naccount\t1\ndatabase\t1\nprivileges\t1\n" if binding_state else "",
        "",
        "/nix/store/fcgi/bin/cgi-fcgi" if binding_state else "",
    )
    return remove.RemovalEvidence(
        None,
        Standing.TARGET_STACK,
        {
            "version": 1,
            "identifier": "alpha",
            "boot": BOOT_ID,
            "uptime": 500025,
            "paths": dict.fromkeys(PATHS, present),
            "names": list(names),
            "https": True,
            "runtime": "php84",
            "problem": "",
            "site_file_digest": DIGEST if present else "",
            "account": [1001, 1001, "/var/www/alpha", "/usr/sbin/nologin", [1001]]
            if present
            else None,
            "proxy_account": [1002, 1002, "/nonexistent", "/usr/sbin/nologin", [1002]]
            if present
            else None,
            "account_group": [1001, []] if present else None,
            "proxy_group": [1002, []] if present else None,
            "certificates": (
                ["/var/lib/caddy/.local/share/caddy/certificates/acme/alpha.example.com"]
                if present
                else []
            ),
            "services": {
                "haproxy-site@alpha.service": ["loaded", "active", "running"],
                "php-fpm-site-php84@alpha.service": ["loaded", "active", "running"],
                "php-fpm-site-php85@alpha.service": ["loaded", "inactive", "dead"],
                "valkey-server@alpha.service": ["loaded", "active", "running"],
            },
            "other_sites": ["beta"],
            "caddy_matches": True,
            "caddy_data_directory": "/var/lib/caddy/.local/share/caddy",
            "digest": DIGEST,
        },
        "",
        database,
    )


def removal_draft() -> ReviewDraft:
    """The removal review of the recorded alpha site."""
    return remove.review(evidence(), PreparationInputs("", "alpha"))
