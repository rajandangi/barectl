"""Drive the four operational change members against one real scenario server."""

import shlex
import time

from operations import engine, native
from operations.inputs import PreparationInputs
from operations.models import ChangeReview

from .scenario_testing import ScenarioTestCase


def apply_change(
    test: ScenarioTestCase, kind: engine.ChangeKind, inputs: PreparationInputs
) -> ChangeReview:
    with test.shell() as shell:
        draft = kind.review(kind.inspect(shell, inputs), inputs)
        test.assertTrue(draft.eligible, draft.refusals)
        stored = ChangeReview(
            document=draft.document,
            sites_read=draft.sites_read,
            sites_digest=engine._sites_digest(shell, draft),
        )
        if not draft.no_changes:
            if draft.uptime_centiseconds is None:
                test.fail("No native clock.")
            context = engine.BodyContext(
                native.new_unit_name(), draft.boot_id, draft.uptime_centiseconds + 90000
            )
            body = kind.body(draft.document, context)
            path = engine.body_path(context.unit)
            digest = str(draft.document["body_sha256"])
            test.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, digest)), stdin=body.source
                ).exit_status,
                0,
            )
            payload = engine.payload(kind, stored, context, body, path)
            test.assertEqual(
                shell.run(
                    shlex.join(native.submission(context.unit, payload, collect=True))
                ).exit_status,
                0,
            )
            end = time.monotonic() + 30
            result = engine.read_result(shell, context.unit)
            while result is None and time.monotonic() < end:
                time.sleep(0.05)
                result = engine.read_result(shell, context.unit)
            if result is None:
                test.fail(
                    "No native outcome: " + test.native(f"journalctl -u {context.unit} -n 30")
                )
            test.assertEqual(result.result_class, "succeeded", result.reason)
        test.assertTrue(kind.verify(shell, stored))
        return stored
