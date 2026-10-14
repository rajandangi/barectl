"""Fast native validators and before-effect refusals in one post-bootstrap container."""

import shlex
import time

from django.test import tag

from sites import observation
from sites.configuration import SiteSettings, render_caddy

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteValidators(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "v338"
    validator = True

    def test_http_renderer_validates_as_the_caddy_service_identity(self) -> None:
        settings = SiteSettings("v338render", ("v338render.example.com",), "php84")
        self.native(
            "install -d -o caddy -g caddy -m 750 /var/www/v338render/logs; "
            "install -d -o root -g caddy -m 750 /run/s4candidate/sites"
        )
        self.native(
            "cp /etc/caddy/Caddyfile /run/s4candidate/Caddyfile; "
            "chown root:caddy /run/s4candidate/Caddyfile; chmod 640 /run/s4candidate/Caddyfile"
        )
        self.native(
            "printf %s "
            + shlex.quote(render_caddy(settings))
            + " >/run/s4candidate/sites/v338render.caddy; "
            "chown root:caddy /run/s4candidate/sites/v338render.caddy; "
            "chmod 640 /run/s4candidate/sites/v338render.caddy"
        )
        self.native(
            "runuser -u caddy -- /nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
            "--config /run/s4candidate/Caddyfile --adapter caddyfile"
        )

    def test_recognition_accepts_formatting_but_refuses_an_added_handler(self) -> None:
        from sites import observation

        settings = SiteSettings("v338alpha", ("v338alpha.example.com",), "php84")
        source = (
            observation.COMMON_SOURCE
            + """
import sys
original = adapt(sys.argv[1])
settings = extract('v338alpha', original)
if original != adapt(caddy_file(settings)):
    raise ValueError('Outside supported settings.')
print(settings.identifier)
"""
        )
        self.assertEqual(
            self.native(
                shlex.join(
                    ["python3", "-c", source, "# An operator comment\n" + render_caddy(settings)]
                )
            ).strip(),
            "v338alpha",
        )
        from .docker import DockerError

        with self.assertRaises(DockerError):
            self.native(
                shlex.join(
                    [
                        "python3",
                        "-c",
                        source,
                        render_caddy(settings).replace(
                            "    route {", "    route {\n        respond /extra unexpected"
                        ),
                    ]
                )
            )

    def test_both_php_branches_and_name_boundaries_validate_and_round_trip(self) -> None:
        long_name = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 49, "example", "com"])
        self.assertEqual(len(long_name), 253)
        for runtime in ("php84", "php85"):
            for names in (
                ("v338matrix.example.com",),
                ("v338matrix.example.com", long_name),
                tuple(f"v338matrix{n}.example.com" for n in range(10)),
            ):
                settings = SiteSettings("v338matrixrender", names, runtime)
                source = (
                    observation.COMMON_SOURCE
                    + """
import sys
original = adapt(sys.argv[1])
settings = extract('v338matrixrender', original)
if original != adapt(caddy_file(settings)):
    raise ValueError('The supported configuration did not round trip.')
validate_candidate(settings.identifier, sys.argv[1])
print(settings.runtime)
"""
                )
                with self.subTest(runtime=runtime, names=len(names)):
                    self.assertEqual(
                        self.native(
                            shlex.join(
                                [
                                    "python3",
                                    "-c",
                                    source,
                                    render_caddy(settings),
                                ]
                            )
                        ).strip(),
                        runtime,
                    )

    def test_exact_future_log_path_validation_never_creates_live_site_resources(self) -> None:
        settings = SiteSettings("v338new", ("v338new.example.com",), "php84")
        before = self.native(
            "cat /proc/1/mountinfo; find /run -maxdepth 1 -name 'site-candidate-*'"
        )
        self.native("test ! -e /var/www/v338new")
        source = (
            observation.COMMON_SOURCE
            + "\nimport sys\nvalidate_candidate(sys.argv[1], sys.argv[2])\n"
        )
        self.native(
            shlex.join(["python3", "-c", source, settings.identifier, render_caddy(settings)])
        )
        self.native("test ! -e /var/www/v338new")
        self.assertEqual(
            self.native("cat /proc/1/mountinfo; find /run -maxdepth 1 -name 'site-candidate-*'"),
            before,
        )

    def test_unavailable_mount_privilege_refuses_and_removes_scratch_artifacts(self) -> None:
        settings = SiteSettings("v338limit", ("v338limit.example.com",), "php84")
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
        self.native("test ! -e /var/www/v338limit")
        self.assertEqual(self.native("find /run -maxdepth 1 -name 'site-candidate-*'"), before)

    def test_future_pool_syntax_is_checked_without_creating_its_account_or_live_files(self) -> None:
        for runtime in ("php84", "php85"):
            settings = SiteSettings("v338pool" + runtime[-2:], ("v338pool.example.com",), runtime)
            source = (
                observation.COMMON_SOURCE
                + """
import sys
settings = setting(sys.argv[1], ['v338pool.example.com'], sys.argv[2])
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

        self.native("install -d -o root -g root -m 755 /var/www")
        for identifier, unsafe in (
            ("v338preimage", "preimage"),
            ("v338unsafe", "configuration"),
            ("v338directory", "site"),
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

    def test_safe_scratch_publication_then_preimage_and_directory_refusals(self) -> None:
        source = (
            observation.COMMON_SOURCE
            + """
with tempfile.TemporaryDirectory(prefix='v338-publication-', dir='/run') as directory:
    root = pathlib.Path(directory)
    root.chmod(0o755)
    target = root / 'site.caddy'
    target.write_text('original')
    target.chmod(0o644)
    if not safe(str(root), directory=True) or not safe(str(target)):
        raise ValueError('The positive scratch baseline is not safe.')
    replace_caddy(target, 'published', 'original')
    if target.read_text() != 'published':
        raise ValueError('Safe scratch publication failed.')
    try:
        replace_caddy(target, 'unexpected', 'original')
    except ValueError:
        result('refused', 'evidence')
    else:
        raise ValueError('Changed preimage was overwritten.')
    root.chmod(0o777)
    try:
        replace_caddy(root / 'other.caddy', 'unexpected', None)
    except ValueError:
        result('refused', 'evidence')
    else:
        raise ValueError('Unsafe scratch directory was published into.')
    root.chmod(0o755)
    if target.read_text() != 'published' or list(root.iterdir()) != [target]:
        raise ValueError('Refusal changed the positive baseline or staged a file.')
"""
        )
        self.assertEqual(
            self.native(shlex.join(["python3", "-c", source])).splitlines(),
            ['barectl-result {"class":"refused","reason":"evidence"}'] * 2,
        )

    def test_caddy_rejects_a_host_defined_by_two_site_blocks(self) -> None:
        first = SiteSettings("v338first", ("v338same.example.com",), "php84")
        second = SiteSettings("v338second", first.names, "php85")
        source = (
            observation.COMMON_SOURCE
            + """
import sys
validate_candidate('v338first', sys.argv[1])
try:
    adapt(sys.argv[1] + sys.argv[2])
except ValueError:
    print('native-duplicate-host-refused')
else:
    raise ValueError('Native Caddy accepted the duplicate host definition.')
"""
        )
        self.assertEqual(
            self.native(
                shlex.join(["python3", "-c", source, render_caddy(first), render_caddy(second)])
            ).strip(),
            "native-duplicate-host-refused",
        )
