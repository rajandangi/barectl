"""Real Caddy parser, publication and plain-PHP site behavior."""

import shlex

from django.test import tag

from sites.configuration import SiteSettings, render_caddy

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteNativeBehavior(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s4"

    def test_http_renderer_validates_as_the_caddy_service_identity(self) -> None:
        settings = SiteSettings("s4alpha", ("s4alpha.example.com",), "php84")
        self.native(
            "install -d -o caddy -g caddy -m 750 /var/www/s4alpha/logs; "
            "install -d -o root -g caddy -m 750 /run/s4candidate/sites"
        )
        self.native(
            "cp /etc/caddy/Caddyfile /run/s4candidate/Caddyfile; "
            "chown root:caddy /run/s4candidate/Caddyfile; chmod 640 /run/s4candidate/Caddyfile"
        )
        self.native(
            "printf %s "
            + shlex.quote(render_caddy(settings))
            + " >/run/s4candidate/sites/s4alpha.caddy; "
            "chown root:caddy /run/s4candidate/sites/s4alpha.caddy; "
            "chmod 640 /run/s4candidate/sites/s4alpha.caddy"
        )
        self.native(
            "runuser -u caddy -- /nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
            "--config /run/s4candidate/Caddyfile --adapter caddyfile"
        )

    def test_recognition_accepts_formatting_but_refuses_an_added_handler(self) -> None:
        from sites import observation

        settings = SiteSettings("s4alpha", ("s4alpha.example.com",), "php84")
        source = (
            observation.COMMON_SOURCE
            + """
original = adapt(sys.argv[1])
settings = extract('s4alpha', original)
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
            "s4alpha",
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

    def test_created_php_site_serves_as_its_reviewed_account(self) -> None:
        from operations.inputs import PreparationInputs
        from sites import change

        inputs = PreparationInputs("php84", "s4alpha", ("s4alpha.example.com",))
        with self.shell() as shell:
            draft = change.review(change.inspect(shell, inputs), inputs)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertFalse(draft.no_changes)
            self.assertEqual(draft.current_sites, ())
            import time

            from operations import engine, native
            from operations.models import ChangeReview

            if draft.uptime_centiseconds is None:
                self.fail("No native clock.")
            context = engine.BodyContext(
                native.new_unit_name(), draft.boot_id, draft.uptime_centiseconds + 90000
            )
            review = ChangeReview(
                document=draft.document,
                sites_read=draft.sites_read,
                sites_digest=engine._sites_digest(shell, draft),
            )
            body = change.body(draft.document, context)
            path = engine.body_path(context.unit)
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, change.BODY_SHA256)), stdin=body.source
                ).exit_status,
                0,
            )
            payload = engine.payload(change.CREATE_SITE, review, context, body, path)
            self.assertEqual(
                shell.run(
                    shlex.join(native.submission(context.unit, payload, collect=True))
                ).exit_status,
                0,
            )
            deadline = time.monotonic() + 30
            outcome = engine.read_result(shell, context.unit)
            while outcome is None and time.monotonic() < deadline:
                time.sleep(0.1)
                outcome = engine.read_result(shell, context.unit)
            self.assertIsNotNone(outcome, self.native(f"journalctl -u {context.unit} -n 40"))
            if outcome is None:
                self.fail("No native result.")
            self.assertEqual(
                outcome.result_class,
                "succeeded",
                self.native(f"journalctl -u {context.unit} -n 40"),
            )
