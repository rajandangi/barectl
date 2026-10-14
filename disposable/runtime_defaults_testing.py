import hashlib
import shlex
import time

from operations import engine, native
from operations.inputs import PreparationInputs
from operations.models import ChangeReview

from .scenario_testing import ScenarioTestCase


class DefaultChangeCase(ScenarioTestCase):
    def apply_change(
        self,
        kind: engine.ChangeKind,
        inputs: PreparationInputs,
        *,
        before_submit: str = "",
    ) -> tuple[engine.ResultLine, dict[str, object]]:
        with self.shell() as shell:
            evidence = kind.inspect(shell, inputs)
            draft = kind.review(evidence, inputs)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertFalse(draft.no_changes)
            context = engine.BodyContext(
                native.new_unit_name(), draft.boot_id, int(draft.uptime_centiseconds or 0) + 90000
            )
            review = ChangeReview(
                document=draft.document,
                sites_read=draft.sites_read,
                sites_digest=hashlib.sha256(
                    "".join(site + "\n" for site in draft.current_sites).encode()
                ).hexdigest()
                if draft.current_sites is not None
                else "",
            )
            body = kind.body(draft.document, context)
            path = engine.body_path(context.unit)
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, hashlib.sha256(body.source).hexdigest())),
                    stdin=body.source,
                ).exit_status,
                0,
            )
            if before_submit:
                self.native(before_submit)
            payload = engine.payload(kind, review, context, body, path)
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
                self.fail(self.native(f"journalctl -u {context.unit} -n 30"))
            return result, draft.document
