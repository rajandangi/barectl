"""Exact future-path validation and rejected Caddy loads preserve native state."""

import shlex

from django.test import tag

from sites import observation
from sites.configuration import SiteSettings, render_caddy

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteTransactions(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s8http"

    def test_native_command_timeout_kills_descendants_before_their_side_effect(self) -> None:
        source = (
            observation.COMMON_SOURCE
            + """
try:
    run(['/bin/sh', '-c', 'sleep 21; touch /run/s8http-late-child'])
except subprocess.TimeoutExpired:
    print('timed-out')
else:
    raise ValueError('The native command exceeded its deadline.')
time.sleep(2)
if pathlib.Path('/run/s8http-late-child').exists():
    raise ValueError('A timed-out descendant survived.')
"""
        )
        self.assertEqual(self.native(observation.python_command(source, ())).strip(), "timed-out")

    def test_valid_candidate_with_rejected_live_load_restores_old_bytes_and_serving(self) -> None:
        settings = SiteSettings("s8httpold", ("s8httpold.example.com",), "php84")
        original = render_caddy(settings)
        self.native(
            "install -d -o root -g root -m 755 /var/www/s8httpold/releases/initial; "
            "install -d -o root -g caddy -m 750 /var/www/s8httpold/releases/initial/public; "
            "install -d -o caddy -g caddy -m 750 /var/www/s8httpold/logs; "
            "ln -s releases/initial /var/www/s8httpold/current; "
            "printf old-serving >/var/www/s8httpold/current/public/hello.txt; "
            "chmod 644 /var/www/s8httpold/current/public/hello.txt"
        )
        path = "/etc/caddy/sites/s8httpold.caddy"
        self.native("printf %s " + shlex.quote(original) + " >" + path + "; chmod 644 " + path)
        self.native(
            "/nix/var/nix/profiles/barectl/caddy/bin/caddy reload "
            "--config /etc/caddy/Caddyfile --adapter caddyfile "
            "--address unix//run/caddy/admin.sock"
        )
        self.native(
            "systemd-run --unit s8http-conflict -- /usr/bin/python3 -m http.server 18089 "
            "--bind 127.0.0.1; "
            "for n in $(seq 1 50); do ss -Hlnpt '( sport = :18089 )' | "
            "grep -q . && break; sleep .05; done; "
            "ss -Hlnpt '( sport = :18089 )' | grep -q ."
        )
        candidate = original.replace(
            "http://s8httpold.example.com", "http://s8httpold.example.com:18089"
        )
        source = (
            observation.COMMON_SOURCE
            + """
import sys
before = adapt()
if before != running():
    raise ValueError('Initial serving state differs.')
if publish_caddy('s8httpold', sys.argv[1], sys.argv[2]):
    raise ValueError('The conflicting live listener was accepted.')
if current_bytes(pathlib.Path('/etc/caddy/sites/s8httpold.caddy')) != sys.argv[2]:
    raise ValueError('Old bytes were not restored.')
if adapt() != before or running() != before:
    raise ValueError('Old serving state was not restored.')
print('restored')
"""
        )
        try:
            self.assertEqual(
                self.native(observation.python_command(source, (candidate, original))).strip(),
                "restored",
            )
            self.assertEqual(
                self.native(
                    "curl --fail --silent -H 'Host: s8httpold.example.com' http://127.0.0.1/hello.txt"
                ),
                "old-serving",
            )
        finally:
            self.native("systemctl stop s8http-conflict.service")
