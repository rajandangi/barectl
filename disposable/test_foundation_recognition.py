"""Foundation adoption requires safe running routes and privileged native evidence."""

import os
import shlex
from dataclasses import replace
from pathlib import Path

from django.test import tag

from bootstrap import foundation
from discovery import ssh

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class FoundationRouteRecognition(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""

    def test_earlier_unmatched_success_route_refuses_foundation_adoption(self) -> None:
        configuration = """{
    admin unix//run/caddy/admin.sock|0600
    auto_https off
    servers {
        strict_sni_host on
    }
}
:80 {
    route {
        respond 200
    }
    respond 404
}
"""
        self.native(
            f"printf %s {shlex.quote(configuration)} >/etc/caddy/Caddyfile; "
            "systemctl reload caddy.service"
        )
        self.assertEqual(
            self.native(
                "curl --silent --output /dev/null --write-out '%{http_code}' "
                "-H 'Host: barectl-unknown.invalid' http://127.0.0.1/"
            ).strip(),
            "200",
        )
        before = self.native("sha256sum /etc/caddy/Caddyfile")
        with self.shell() as shell:
            evidence = foundation.inspect(shell)
            draft = foundation.review(evidence)
        self.assertFalse(evidence.complete)
        self.assertFalse(draft.eligible)
        self.assertFalse(draft.no_changes)
        self.assertTrue(draft.refusals)
        self.assertEqual(self.native("sha256sum /etc/caddy/Caddyfile"), before)


@tag(SCENARIO_TAG)
class FoundationDeniedPrivilege(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""

    def test_authenticated_user_without_sudo_cannot_adopt_or_mutate_foundation(self) -> None:
        target = self.target()
        public = Path(f"{target.identity_files[0]}.pub").read_text().strip()
        self.native(
            "useradd --create-home --shell /bin/bash foundation-denied; "
            "install -d -m 700 -o foundation-denied -g foundation-denied "
            "/home/foundation-denied/.ssh; "
            f"printf '%s\\n' {shlex.quote(public)} "
            ">/home/foundation-denied/.ssh/authorized_keys; "
            "chown foundation-denied:foundation-denied "
            "/home/foundation-denied/.ssh/authorized_keys; "
            "chmod 600 /home/foundation-denied/.ssh/authorized_keys"
        )
        before = self.native(
            "sha256sum /etc/caddy/Caddyfile /etc/nix/nix.conf "
            "/etc/systemd/journald.conf.d/50-barectl.conf"
        )
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(replace(target, user="foundation-denied")) as shell:
            self.assertEqual(shell.run("id -un").stdout.strip(), "foundation-denied")
            self.assertNotEqual(shell.run("sudo -n true").exit_status, 0)
            evidence = foundation.inspect(shell)
            draft = foundation.review(evidence)
        self.assertFalse(evidence.complete)
        self.assertFalse(draft.eligible)
        self.assertFalse(draft.no_changes)
        self.assertIn(
            "The discovery connection has neither root nor authorized passwordless sudo.",
            draft.refusals,
        )
        self.assertEqual(
            self.native(
                "sha256sum /etc/caddy/Caddyfile /etc/nix/nix.conf "
                "/etc/systemd/journald.conf.d/50-barectl.conf"
            ),
            before,
        )
