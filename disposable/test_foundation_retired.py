"""A newer controller recognizes known retired foundation tools from native evidence."""

import shlex
import time
from dataclasses import replace
from unittest.mock import patch

from django.test import tag

from bootstrap import foundation
from operations import engine, native
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of, load

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class RetiredFoundationRecognition(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""

    def test_an_earlier_main_configuration_is_finished_by_a_caddy_refresh(self) -> None:
        old = (
            "{\n"
            "\tadmin unix//run/caddy/admin.sock|0600\n"
            "\tauto_https off\n"
            "\tservers {\n\t\tstrict_sni_host on\n\t}\n"
            "}\n"
            "import sites/*.caddy\n"
            ":80 {\n\trespond 404\n}\n"
        )
        self.native("printf %s " + shlex.quote(old) + " >/etc/caddy/Caddyfile")
        self.native(
            "/nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
            "--config /etc/caddy/Caddyfile --adapter caddyfile"
        )
        self.native("systemctl reload caddy")
        with self.shell() as shell:
            evidence = foundation.inspect(shell)
            self.assertEqual(evidence.caddy_shape, "older", evidence)
            self.assertFalse(evidence.complete)
            review = foundation.review(evidence)
            self.assertTrue(review.eligible, review.refusals)
            self.assertEqual(review.document["caddy_mode"], "refresh")
            context = engine.BodyContext(
                native.new_unit_name(),
                evidence.boot_id,
                (evidence.uptime_centiseconds or 0) + 90000,
            )
            record = ChangeReview(document=review.document, sites_read="", sites_digest="")
            body = foundation.body(record.document, context)
            path = engine.body_path(context.unit)
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, foundation.BODY_SHA256)),
                    stdin=body.source,
                ).exit_status,
                0,
            )
            payload = engine.payload(foundation.HOST_FOUNDATION, record, context, body, path)
            self.assertEqual(
                shell.run(
                    shlex.join(native.submission(context.unit, payload, collect=True))
                ).exit_status,
                0,
            )
            deadline = time.monotonic() + 30
            result = engine.read_result(shell, context.unit)
            while result is None and time.monotonic() < deadline:
                time.sleep(0.1)
                result = engine.read_result(shell, context.unit)
            if result is None:
                self.fail(
                    "No refresh outcome: " + self.native(f"journalctl -u {context.unit} -n 40")
                )
            self.assertEqual(result.result_class, "succeeded", result.reason)
            self.assertTrue(foundation.verify(shell, record))
            finished = foundation.inspect(shell)
            self.assertTrue(finished.complete)
            self.assertEqual(finished.caddy_shape, "supported")

    def test_known_retired_native_profiles_remain_complete_without_reinstallation(self) -> None:
        catalog = load()
        with self.shell() as shell:
            values = foundation.read(shell)
            self.assertIsNotNone(values)
            if values is None:
                self.fail("The native foundation could not be read.")
            architecture = architecture_of(values["architecture"])
            if architecture is None:
                self.fail("The native architecture is unsupported.")
            retired = replace(
                catalog,
                builds=tuple(
                    replace(build, retired=True)
                    if build.entry in foundation.PROFILES and build.architecture == architecture
                    else build
                    for build in catalog.builds
                )
                + tuple(
                    replace(build, path=build.path + "-next")
                    for build in catalog.offered(architecture)
                    if build.entry in foundation.PROFILES
                ),
            )
            with patch("bootstrap.foundation.load", return_value=retired):
                evidence = foundation.inspect(shell)
                self.assertTrue(evidence.complete)
                review = foundation.review(evidence)
                self.assertTrue(review.no_changes)
                self.assertEqual(
                    review.document["profiles"],
                    {entry: values[entry] for entry in foundation.PROFILES},
                )
                for entry in foundation.PROFILES:
                    with self.subTest(entry=entry):
                        self.assertFalse(
                            foundation.complete(
                                {**values, entry: "/nix/store/unknown"}, architecture
                            )
                        )
                self.assertFalse(
                    foundation.complete({**values, "composer": values["wp-cli"]}, architecture)
                )
                self.assertFalse(
                    foundation.complete({**values, "caddy_version": "v0.0.0"}, architecture)
                )
                self.assertFalse(
                    foundation.complete(
                        values,
                        Architecture.AARCH64
                        if architecture == Architecture.X86_64
                        else Architecture.X86_64,
                    )
                )
                self.native(
                    "rm /etc/systemd/journald.conf.d/50-barectl.conf; "
                    "systemctl restart systemd-journald.service"
                )
                partial = foundation.inspect(shell)
                retry = foundation.review(partial)
                self.assertTrue(retry.eligible, retry.refusals)
                self.assertFalse(retry.no_changes)
                self.assertEqual(retry.document["profiles"], review.document["profiles"])
                context = engine.BodyContext(
                    native.new_unit_name(),
                    partial.boot_id,
                    (partial.uptime_centiseconds or 0) + 90000,
                )
                record = ChangeReview(document=retry.document, sites_read="", sites_digest="")
                body = foundation.body(record.document, context)
                path = engine.body_path(context.unit)
                self.assertEqual(
                    shell.run(
                        shlex.join(engine.stage_command(path, foundation.BODY_SHA256)),
                        stdin=body.source,
                    ).exit_status,
                    0,
                )
                payload = engine.payload(foundation.HOST_FOUNDATION, record, context, body, path)
                self.assertEqual(
                    shell.run(
                        shlex.join(native.submission(context.unit, payload, collect=True))
                    ).exit_status,
                    0,
                )
                deadline = time.monotonic() + 30
                result = engine.read_result(shell, context.unit)
                while result is None and time.monotonic() < deadline:
                    time.sleep(0.1)
                    result = engine.read_result(shell, context.unit)
                self.assertIsNotNone(result, self.native(f"journalctl -u {context.unit} -n 40"))
                if result is not None:
                    self.assertEqual(result.result_class, "succeeded")
                self.assertTrue(foundation.verify(shell, record))
            after = foundation.read(shell)
            self.assertIsNotNone(after)
            if after is not None:
                self.assertEqual(after["digest"], values["digest"])
