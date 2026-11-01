"""The prepared WordPress identity and its HTTPS fixture configuration."""

import shlex

from automation import change
from automation.convention import service_name
from operations.inputs import PreparationInputs
from sites.configuration import SiteSettings, render_wordpress_caddy

from .change_testing import submit_change, wait_result
from .scenario_testing import ScenarioTestCase

WORDPRESS_SITE = "l3wordpress"
WORDPRESS_DOMAIN = "site.fixture.test"
WORDPRESS_TITLE = "Barectl cached fixture"
WORDPRESS_ADMIN = "barectladmin"
WORDPRESS_EMAIL = "admin@example.com"


def prepare_wordpress_https(test: ScenarioTestCase) -> str:
    """Serve L3's product-created site over the lane's real fixture HTTPS endpoint."""
    settings = SiteSettings(WORDPRESS_SITE, (WORDPRESS_DOMAIN,), "php84")
    with test.shell() as shell:
        written = shell.run(
            f"install -D -m 0644 /dev/stdin /etc/caddy/sites/{WORDPRESS_SITE}.caddy 2>&1",
            stdin=render_wordpress_caddy(settings).encode(),
        )
        test.assertEqual(written.exit_status, 0, written.stdout)
    test.native(
        "/nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
        "--config /etc/caddy/Caddyfile --adapter caddyfile"
    )
    test.native("systemctl reload caddy")
    wp = (
        f"runuser -u s{WORDPRESS_SITE} -- /var/www/{WORDPRESS_SITE}/bin/wp "
        f"--path=/var/www/{WORDPRESS_SITE}/current/public"
    )
    for option in ("home", "siteurl"):
        test.native(f"{wp} option update {option} {shlex.quote(f'https://{WORDPRESS_DOMAIN}')}")
    return test.native(
        "curl --silent --show-error --fail --max-time 20 --insecure "
        "--retry 10 --retry-all-errors --retry-delay 1 "
        f"--resolve {WORDPRESS_DOMAIN}:443:127.0.0.1 https://{WORDPRESS_DOMAIN}/"
    )


def start_wordpress_cron_for_fence(test: ScenarioTestCase) -> None:
    """C3 needs enabled cron; C1 separately proves automatic calendar initiation (#357)."""
    kind = change.SET_WORDPRESS_SERVER_CRON
    submitted = submit_change(
        test, kind, PreparationInputs("", WORDPRESS_SITE, schedule_state="on")
    )
    test.assertFalse(submitted.no_changes)
    journal = shlex.join(("journalctl", "-u", submitted.unit, "--no-pager", "-o", "cat"))
    service = service_name(WORDPRESS_SITE, "wpcron")
    stimulus = (
        f"until {journal} --grep='^barectl-stage tick$' >/dev/null; do sleep 0.1; done; "
        f"until {journal} --grep='^barectl-result ' >/dev/null; do "
        f"systemctl start {shlex.quote(service)}; sleep 1; done"
    )
    test.native("timeout 150 sh -ec " + shlex.quote(stimulus), timeout=155)
    wait_result(test, submitted, timeout=180)
    with test.shell() as shell:
        test.assertTrue(kind.verify(shell, submitted.review))
