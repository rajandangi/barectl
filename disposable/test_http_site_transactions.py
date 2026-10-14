"""Exact future-path validation and rejected Caddy loads preserve native state."""

import shlex
import time

from django.test import tag

from sites import observation
from sites.configuration import SiteSettings, render_caddy

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteTransactions(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s8http"

    def test_exact_future_log_path_validation_never_creates_live_site_resources(self) -> None:
        settings = SiteSettings("s8httpnew", ("s8httpnew.example.com",), "php84")
        before = self.native(
            "cat /proc/1/mountinfo; find /run -maxdepth 1 -name 'site-candidate-*'"
        )
        self.native("test ! -e /var/www/s8httpnew")
        source = (
            observation.COMMON_SOURCE
            + "\nimport sys\nvalidate_candidate(sys.argv[1], sys.argv[2])\n"
        )
        self.native(
            shlex.join(["python3", "-c", source, settings.identifier, render_caddy(settings)])
        )
        self.native("test ! -e /var/www/s8httpnew")
        self.assertEqual(
            self.native("cat /proc/1/mountinfo; find /run -maxdepth 1 -name 'site-candidate-*'"),
            before,
        )

    def test_unavailable_mount_privilege_refuses_and_removes_scratch_artifacts(self) -> None:
        settings = SiteSettings("s8httplimit", ("s8httplimit.example.com",), "php84")
        before = self.native("find /run -maxdepth 1 -name 'site-candidate-*'")
        source = (
            observation.COMMON_SOURCE
            + """
import sys
try:
    validate_candidate(sys.argv[1], sys.argv[2])
except ValueError:
    print('unavailable')
else:
    raise ValueError('Validation unexpectedly bypassed missing mount privilege.')
"""
        )
        self.assertEqual(
            self.native(
                shlex.join(
                    [
                        "/usr/bin/setpriv",
                        "--bounding-set=-sys_admin",
                        "python3",
                        "-c",
                        source,
                        settings.identifier,
                        render_caddy(settings),
                    ]
                )
            ).strip(),
            "unavailable",
        )
        self.native("test ! -e /var/www/s8httplimit")
        self.assertEqual(self.native("find /run -maxdepth 1 -name 'site-candidate-*'"), before)

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
        self.assertEqual(self.native(shlex.join(["python3", "-c", source])).strip(), "timed-out")

    def test_future_pool_syntax_is_checked_without_creating_its_account_or_live_files(self) -> None:
        for runtime in ("php84", "php85"):
            settings = SiteSettings(
                "s8httppool" + runtime[-2:], ("s8httppool.example.com",), runtime
            )
            source = (
                observation.COMMON_SOURCE
                + """
import sys
settings = setting(sys.argv[1], ['s8httppool.example.com'], sys.argv[2])
identity = free_identity()
before = native_state(settings.identifier, settings.runtime)['digest']
validate_pool_candidate(settings, identity, pool_file(settings))
try:
    invalid = pool_file(settings).replace('pm.max_children = 2', 'pm.max_children = 0')
    validate_pool_candidate(settings, identity, invalid)
except ValueError:
    pass
else:
    raise ValueError('Native PHP-FPM accepted an invalid child count.')
if native_state(settings.identifier, settings.runtime)['digest'] != before:
    raise ValueError('Scratch validation changed live configuration or identities.')
if pathlib.Path(settings.directory).exists():
    raise ValueError('Scratch validation created a live site.')
try:
    pwd.getpwnam(settings.account)
except KeyError:
    pass
else:
    raise ValueError('Scratch validation created an account.')
print('refused-without-live-mutation')
"""
            )
            before_mounts = self.native("cat /proc/1/mountinfo")
            self.assertEqual(
                self.native(
                    shlex.join(
                        [
                            "python3",
                            "-c",
                            source,
                            settings.identifier,
                            settings.runtime,
                        ]
                    )
                ).strip(),
                "refused-without-live-mutation",
            )
            self.assertEqual(self.native("cat /proc/1/mountinfo"), before_mounts)
            self.native("test -z \"$(find /run -maxdepth 1 -name 'site-pool-candidate-*')\"")

    def test_changed_preimage_and_unsafe_directory_refuse_before_persistent_mutation(self) -> None:
        from operations import engine, native
        from operations.inputs import PreparationInputs
        from operations.models import ChangeReview
        from sites import change

        for identifier, unsafe in (
            ("s8httppreimage", "preimage"),
            ("s8httpunsafe", "configuration"),
            ("s8httpdirectory", "site"),
        ):
            inputs = PreparationInputs("php84", identifier, (identifier + ".example.com",))
            with self.shell() as shell:
                draft = change.review(change.inspect(shell, inputs), inputs)
                self.assertTrue(draft.eligible, draft.refusals)
                if draft.uptime_centiseconds is None:
                    self.fail("No native clock.")
                context = engine.BodyContext(
                    native.new_unit_name(), draft.boot_id, draft.uptime_centiseconds + 90000
                )
                stored = ChangeReview(
                    document=draft.document,
                    sites_read=draft.sites_read,
                    sites_digest=engine._sites_digest(shell, draft),
                )
                body = change.body(draft.document, context)
                path = engine.body_path(context.unit)
                original = self.native("cat /etc/caddy/Caddyfile")
                if unsafe == "configuration":
                    self.native("chmod 777 /etc/caddy/sites")
                elif unsafe == "site":
                    self.native(
                        f"install -d -m 777 /var/www/{identifier}; "
                        f"printf foreign-content >/var/www/{identifier}/preserve.txt"
                    )
                else:
                    self.native("printf '\n# external native edit\n' >>/etc/caddy/Caddyfile")
                before = self.native(
                    "sha256sum /etc/passwd /etc/group /etc/shadow /etc/caddy/Caddyfile; "
                    "stat -c '%a:%u:%g' /etc/caddy/sites; "
                    "find /etc/php-fpm -type f -exec sha256sum {} +"
                )
                try:
                    self.assertEqual(
                        shell.run(
                            shlex.join(engine.stage_command(path, change.BODY_SHA256)),
                            stdin=body.source,
                        ).exit_status,
                        0,
                    )
                    script = engine.payload(change.CREATE_SITE, stored, context, body, path)
                    self.assertEqual(
                        shell.run(
                            shlex.join(native.submission(context.unit, script, collect=True))
                        ).exit_status,
                        0,
                    )
                    deadline = time.monotonic() + 30
                    outcome = engine.read_result(shell, context.unit)
                    while outcome is None and time.monotonic() < deadline:
                        time.sleep(0.1)
                        outcome = engine.read_result(shell, context.unit)
                    if outcome is None:
                        self.fail("No native preflight refusal outcome.")
                    self.assertEqual(outcome.result_class, "refused", outcome.reason)
                    if unsafe == "site":
                        self.assertEqual(
                            self.native(f"cat /var/www/{identifier}/preserve.txt"),
                            "foreign-content",
                        )
                        self.assertEqual(
                            self.native(f"stat -c '%a:%u:%g' /var/www/{identifier}").strip(),
                            "777:0:0",
                        )
                    else:
                        self.native(f"test ! -e /var/www/{identifier}")
                    self.native(
                        f"test ! -e /etc/caddy/sites/{identifier}.caddy; "
                        f"! getent passwd s{identifier}; ! getent group s{identifier}"
                    )
                    self.assertEqual(
                        self.native(
                            "sha256sum /etc/passwd /etc/group /etc/shadow /etc/caddy/Caddyfile; "
                            "stat -c '%a:%u:%g' /etc/caddy/sites; "
                            "find /etc/php-fpm -type f -exec sha256sum {} +"
                        ),
                        before,
                    )
                finally:
                    self.native("chmod 755 /etc/caddy/sites")
                    self.native("printf %s " + shlex.quote(original) + " >/etc/caddy/Caddyfile")
                    if unsafe == "site":
                        self.native(
                            f"rm /var/www/{identifier}/preserve.txt; rmdir /var/www/{identifier}"
                        )

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
                self.native(shlex.join(["python3", "-c", source, candidate, original])).strip(),
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
