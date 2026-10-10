"""Native disposable-server fixtures for TLS qualification."""

from disposable import acme

from . import renewal

SHORT_AUTHORITY = {
    "directory": acme.SHORT_DIRECTORY,
    "caa": "pebble",
    "name": "Pebble short",
}

# The administrator's own undoing of a setup, so that each test starts without Certbot.
PURGE = "; ".join(
    (
        "systemctl unmask --runtime certbot.timer certbot.service >/dev/null 2>&1",
        "rm -rf /run/systemd/system/certbot.timer.d /run/systemd/system/certbot.service.d",
        "systemctl disable --now certbot.timer >/dev/null 2>&1",
        "systemctl stop certbot.service >/dev/null 2>&1",
        "systemctl reset-failed certbot.service certbot.timer >/dev/null 2>&1",
        (
            "DEBIAN_FRONTEND=noninteractive apt-get -q -y purge --autoremove certbot "
            "python3-certbot python3-acme >/dev/null 2>&1"
        ),
        f"rm -rf {renewal.DROP_IN_DIRECTORY} {renewal.WRAPPER} {renewal.DEPLOY_HOOK}",
        "rm -rf /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt",
        "rm -f /etc/systemd/system/timers.target.wants/certbot.timer",
        "systemctl daemon-reload",
        "true",
    )
)
