"""Real Caddy parser, publication and plain-PHP site behavior."""

import shlex

from django.test import tag

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteNativeBehavior(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s4"
    records: tuple[str, ...] = ("http-site-26.04",)

    def test_created_php_site_serves_as_its_reviewed_account(self) -> None:
        from operations.inputs import PreparationInputs
        from sites import change, observation

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
            raced_inputs = PreparationInputs("php84", "s4raced", ("s4raced.example.com",))
            raced = change.review(change.inspect(shell, raced_inputs), raced_inputs)
            self.assertTrue(raced.eligible, raced.refusals)
            self.assertEqual(raced.current_sites, ())
            raced_review = ChangeReview(
                document=raced.document,
                sites_read=raced.sites_read,
                sites_digest=engine._sites_digest(shell, raced),
            )
            raced_context = engine.BodyContext(
                native.new_unit_name(), draft.boot_id, draft.uptime_centiseconds + 90000
            )
            raced_body = change.body(raced.document, raced_context)
            raced_path = engine.body_path(raced_context.unit)
            raced_payload = engine.payload(
                change.CREATE_SITE, raced_review, raced_context, raced_body, raced_path
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
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(raced_path, change.BODY_SHA256)),
                    stdin=raced_body.source,
                ).exit_status,
                0,
            )
            self.assertEqual(
                shell.run(
                    shlex.join(
                        native.submission(
                            raced_context.unit,
                            raced_payload,
                            collect=True,
                        )
                    )
                ).exit_status,
                0,
            )
            race_deadline = time.monotonic() + 30
            race_result = engine.read_result(shell, raced_context.unit)
            while race_result is None and time.monotonic() < race_deadline:
                time.sleep(0.1)
                race_result = engine.read_result(shell, raced_context.unit)
            if race_result is None:
                self.fail("No native membership-race outcome.")
            self.assertEqual(
                (race_result.result_class, race_result.reason), ("refused", "affected_sites")
            )
            self.native("test ! -e /var/www/s4raced; ! getent passwd ss4raced")
            import json

            response = json.loads(
                self.native("curl --fail --silent -H 'Host: s4alpha.example.com' http://127.0.0.1/")
            )
            self.assertEqual(response["site"], inputs.identifier)
            self.assertEqual(response["uid"], draft.document["identity"])
            self.assertTrue(change.verify(shell, review))
            limited_inputs = PreparationInputs("php84", "s4limited", ("s4limited.example.com",))
            limited = change.review(change.inspect(shell, limited_inputs), limited_inputs)
            self.assertTrue(limited.eligible, limited.refusals)
            limited_context = engine.BodyContext(
                native.new_unit_name(), draft.boot_id, draft.uptime_centiseconds + 90000
            )
            limited_review = ChangeReview(
                document=limited.document,
                sites_read=limited.sites_read,
                sites_digest=engine._sites_digest(shell, limited),
            )
            limited_body = change.body(limited.document, limited_context)
            limited_path = engine.body_path(limited_context.unit)
            limited_payload = engine.payload(
                change.CREATE_SITE, limited_review, limited_context, limited_body, limited_path
            )
            self.assertEqual(
                shell.run(
                    shlex.join(
                        engine.stage_command(
                            limited_path,
                            change.BODY_SHA256,
                        )
                    ),
                    stdin=limited_body.source,
                ).exit_status,
                0,
            )
            limited_submission = native.submission(
                limited_context.unit, limited_payload, collect=True
            )
            limited_submission.insert(1, "--property=CapabilityBoundingSet=~CAP_SYS_ADMIN")
            self.assertEqual(shell.run(shlex.join(limited_submission)).exit_status, 0)
            limited_deadline = time.monotonic() + 30
            limited_result = engine.read_result(shell, limited_context.unit)
            while limited_result is None and time.monotonic() < limited_deadline:
                time.sleep(0.1)
                limited_result = engine.read_result(shell, limited_context.unit)
            if limited_result is None:
                self.fail("No native unavailable-validator outcome.")
            self.assertEqual(limited_result.result_class, "refused")
            self.native("test ! -e /var/www/s4limited; ! getent passwd ss4limited")
            repeated = change.review(change.inspect(shell, inputs), inputs)
            self.assertTrue(repeated.eligible, repeated.refusals)
            self.assertTrue(repeated.no_changes)
            from discovery.observations import collect

            with self.shell() as fresh:
                observed = collect(fresh)
                self.assertEqual(observed.sites.value[0].identifier, inputs.identifier)
                self.assertEqual(observed.sites.value[0].readiness, "/")
                reconstructed = change.review(change.inspect(fresh, inputs), inputs)
                self.assertTrue(reconstructed.no_changes, reconstructed.refusals)
                self.checkpoint("http-site-26.04", fresh)
            # A site whose code answers 500 at its readiness path fails the check. The
            # original placeholder is restored so later scenarios see the recorded site.
            placeholder = "/var/www/s4alpha/current/public/index.php"
            original = self.native("cat " + placeholder)
            try:
                self.native(
                    "runuser -u ss4alpha -- sh -c "
                    + shlex.quote(
                        "printf %s "
                        + shlex.quote("<?php http_response_code(500); echo 'failed';")
                        + " > "
                        + shlex.quote(placeholder)
                    )
                )
                failure = self.native(
                    observation.python_command(
                        observation.COMMON_SOURCE
                        + """
try:
    verify_readiness(setting('s4alpha', ['s4alpha.example.com'], 'php84', https=False))
except ValueError as error:
    print(error)
else:
    raise SystemExit('the readiness check unexpectedly passed')
""",
                        (),
                    )
                )
                self.assertIn("500", failure)
            finally:
                self.native(
                    "runuser -u ss4alpha -- sh -c "
                    + shlex.quote(
                        "printf %s " + shlex.quote(original) + " > " + shlex.quote(placeholder)
                    )
                )
            # A changed readiness path is one reviewed Site change, published as native
            # Caddy evidence and reconstructed by a fresh controller.
            from operations import engine, native
            from operations.models import ChangeReview
            from sites import readiness_change

            readiness_inputs = PreparationInputs("", inputs.identifier, readiness="/hello.txt")
            with self.shell() as change_shell:
                draft = readiness_change.review(
                    readiness_change.inspect(change_shell, readiness_inputs), readiness_inputs
                )
                self.assertTrue(draft.eligible, draft.refusals)
                self.assertFalse(draft.no_changes)
                context = engine.BodyContext(
                    native.new_unit_name(), draft.boot_id, (draft.uptime_centiseconds or 0) + 90000
                )
                body = readiness_change.body(draft.document, context)
                path = engine.body_path(context.unit)
                review = ChangeReview(
                    document=draft.document,
                    sites_read=draft.sites_read,
                    sites_digest=engine._sites_digest(change_shell, draft),
                )
                payload = engine.payload(
                    readiness_change.SET_SITE_READINESS, review, context, body, path
                )
                self.assertEqual(
                    change_shell.run(
                        shlex.join(engine.stage_command(path, readiness_change.BODY_SHA256)),
                        stdin=body.source,
                    ).exit_status,
                    0,
                )
                self.assertEqual(
                    change_shell.run(
                        shlex.join(native.submission(context.unit, payload))
                    ).exit_status,
                    0,
                )
                readiness_deadline = time.monotonic() + 30
                outcome = engine.read_result(change_shell, context.unit)
                while outcome is None and time.monotonic() < readiness_deadline:
                    time.sleep(0.1)
                    outcome = engine.read_result(change_shell, context.unit)
                if outcome is None:
                    self.fail(self.native(f"journalctl -u {context.unit} -n 40"))
                self.assertEqual(
                    (outcome.result_class, outcome.reason),
                    ("succeeded", ""),
                    self.native(f"journalctl -u {context.unit} -n 40"),
                )
                repeated = readiness_change.review(
                    readiness_change.inspect(change_shell, readiness_inputs), readiness_inputs
                )
                self.assertTrue(repeated.eligible, repeated.refusals)
                self.assertTrue(repeated.no_changes)
            with self.shell() as fresh:
                self.assertEqual(
                    collect(fresh).sites.value[0].readiness,
                    "/hello.txt",
                )

    def test_site_php_settings_reload_only_its_own_master_and_reconstruct(self) -> None:
        from discovery.observations import collect
        from operations.inputs import PreparationInputs
        from sites.bodies.pool import SitePool
        from sites.pool_change import SET_SITE_POOL

        from .change_testing import apply_change

        selected = SitePool(
            process_manager="static",
            max_children=4,
            slowlog_timeout=5,
            terminate_timeout=120,
            memory_limit=256,
            upload_max_filesize=32,
            post_max_size=32,
        )
        masters = (
            "systemctl show php-fpm-site-php84@s4alpha.service php-fpm@php84.service "
            "-p MainPID -p InvocationID"
        )
        before = self.native(masters)
        apply_change(self, SET_SITE_POOL, PreparationInputs("", "s4alpha", pool=selected))
        self.assertEqual(self.native(masters), before)
        with self.shell() as fresh:
            observed = collect(fresh).sites.value
            self.assertEqual(observed[0].pool, selected)
            repeated = SET_SITE_POOL.review(
                SET_SITE_POOL.inspect(fresh, PreparationInputs("", "s4alpha", pool=selected)),
                PreparationInputs("", "s4alpha", pool=selected),
            )
            self.assertTrue(repeated.no_changes, repeated.refusals)
        pool = self.native("cat /etc/php-fpm/sites/s4alpha/php84/pools/s4alpha.conf")
        self.assertIn("pm.max_children = 4\n", pool)
        self.assertIn("request_terminate_timeout = 120s\n", pool)
        self.assertIn("php_admin_value[memory_limit] = 256M\n", pool)

    def test_site_pool_settings_then_a_php_switch_uses_the_new_child_count(self) -> None:
        from operations.inputs import PreparationInputs
        from sites.bodies.pool import SitePool
        from sites.php_change import SET_SITE_PHP
        from sites.pool_change import SET_SITE_POOL

        from .change_testing import apply_change

        pool = SitePool(
            process_manager="static",
            max_children=4,
            slowlog_timeout=5,
            terminate_timeout=120,
            memory_limit=256,
            upload_max_filesize=32,
            post_max_size=32,
        )
        apply_change(self, SET_SITE_POOL, PreparationInputs("", "s4alpha", pool=pool))
        for runtime in ("php85", "php84"):
            apply_change(self, SET_SITE_PHP, PreparationInputs(runtime, "s4alpha"))

    def test_site_specific_pool_setting_reports_the_site_without_faulting_its_master(self) -> None:
        from runtimes import observation as runtime_observation
        from runtimes.catalog import architecture_of
        from sites import observation

        pool = "/etc/php-fpm/sites/s4alpha/php84/pools/s4alpha.conf"
        original = self.native("cat " + pool)
        try:
            self.native(
                "printf %s "
                + shlex.quote(original + "\nphp_admin_value[max_execution_time] = 45\n")
                + " >"
                + pool
                + "; systemctl restart php-fpm-site-php84@s4alpha.service"
            )
            with self.shell() as shell:
                sites = observation.observed_sites(shell)
                architecture = architecture_of(self.native("uname -m").strip())
                if architecture is None:
                    self.fail("No supported architecture.")
                runtime = runtime_observation.read(shell, "php84", architecture)
            alpha = [site for site in sites.value if site.identifier == "s4alpha"]
            self.assertEqual(len(alpha), 1)
            self.assertEqual(str(alpha[0].state), "not_following")
            self.assertIn("pool", " ".join(alpha[0].missing))
            if runtime is None:
                self.fail("The independent master's evidence disappeared.")
            php = [
                row
                for row in runtime_observation.observations(runtime["runtimes"], architecture)
                if row.entry == "php84"
            ]
            self.assertEqual(len(php), 1)
            self.assertTrue(php[0].manageable, php[0].problem)
        finally:
            self.native(
                "printf %s "
                + shlex.quote(original)
                + " >"
                + pool
                + "; systemctl restart php-fpm-site-php84@s4alpha.service"
            )
