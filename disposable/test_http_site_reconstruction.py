"""Both native PHP branches reconstruct independently of another master's unsafe pool."""

import shlex
import time

from django.test import tag

from discovery.models import SiteState
from discovery.observations import collect
from operations import engine, native
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from runtimes import observation as runtime_observation
from runtimes.catalog import architecture_of
from sites import change
from sites.configuration import SiteSettings

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteReconstruction(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s4matrix"
    records: tuple[str, ...] = ("http-site-unsafe-master-26.04",)

    def create(self, settings: SiteSettings) -> None:
        inputs = PreparationInputs(settings.runtime, settings.identifier, settings.names)
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
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, change.BODY_SHA256)), stdin=body.source
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
                self.fail("No native create outcome.")
            self.assertEqual(outcome.result_class, "succeeded", outcome.reason)
            self.assertTrue(change.verify(shell, stored))

    def test_unsafe_php84_pool_does_not_hide_a_healthy_php85_site(self) -> None:
        self.create(SiteSettings("s4matrix84", ("s4matrix84.example.com",), "php84"))
        self.create(
            SiteSettings(
                "s4matrix85", ("s4matrix85.example.com", "www.s4matrix85.example.com"), "php85"
            )
        )
        pool = "/etc/php-fpm/sites/s4matrix84/php84/pools/s4matrix84.conf"
        original = self.native("cat " + pool)
        self.native(
            "printf %s "
            + shlex.quote(original.replace("user = ss4matrix84", "user = root"))
            + " >"
            + pool
        )
        try:
            with self.shell() as shell:
                observed = collect(shell).sites
                sites = {site.identifier: site for site in observed.value}
                self.assertEqual(set(sites), {"s4matrix84", "s4matrix85"}, observed.warning)
                self.assertEqual(sites["s4matrix84"].state, SiteState.NOT_FOLLOWING)
                self.assertEqual(sites["s4matrix85"].state, SiteState.MANAGED)
                architecture = architecture_of(self.native("uname -m").strip())
                if architecture is None:
                    self.fail("No supported native architecture.")
                runtime = runtime_observation.read(shell, "php85", architecture)
                if runtime is None:
                    self.fail("Independent runtime evidence disappeared.")
                rows = {
                    row.entry: row
                    for row in runtime_observation.observations(runtime["runtimes"], architecture)
                }
                self.assertTrue(rows["php84"].manageable, rows["php84"].problem)
                self.assertTrue(rows["php85"].manageable, rows["php85"].problem)
                self.checkpoint("http-site-unsafe-master-26.04", shell)
        finally:
            self.native(
                "printf %s "
                + shlex.quote(original)
                + " >"
                + pool
                + "; systemctl restart php-fpm-site-php84@s4matrix84.service"
            )
