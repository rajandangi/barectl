"""The journal retention setting on a real host, through the real change engine (#550).

docs/adr/0044-own-journald-log-retention-in-a-separate-drop-in.md. One L1 lifecycle proves
the applied pair, the manual vacuum boundary, an outside hand edit, a later drop-in that
makes the reviewed body refuse before writing, and fresh-controller reconstruction.
"""

import shlex

from django.test import tag

from discovery.observations import collect
from logs import journal_retention
from logs.journal_retention_change import SET_JOURNAL_RETENTION
from logs.journal_retention_change import inspect as inspect_retention
from logs.journal_retention_change import review as review_retention
from operations import engine
from operations.inputs import PreparationInputs

from .change_testing import apply_change, submit_draft, wait_result
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

LATER_DROP_IN = "/etc/systemd/journald.conf.d/70-operator.conf"


@tag(SCENARIO_TAG)
class JournalRetentionLifecycle(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s548"
    records: tuple[str, ...] = ()

    def test_apply_vacuum_edit_restore_and_later_override(self) -> None:
        self.addCleanup(
            self.native,
            f"rm -f {shlex.quote(journal_retention.RETENTION_PATH)} "
            f"{shlex.quote(LATER_DROP_IN)}; systemctl restart systemd-journald.service || true",
        )
        pair = ("1G", "3months")
        rendered = journal_retention.render(*pair)

        apply_change(
            self,
            SET_JOURNAL_RETENTION,
            PreparationInputs(disk_cap=pair[0], max_age=pair[1]),
        )

        # The applied file is exactly what the pure seam renders, owned root:root 0644.
        self.assertEqual(
            self.native(f"stat -c '%U:%G %a' {journal_retention.RETENTION_PATH}").strip(),
            "root:root 644",
        )
        self.assertEqual(self.native(f"cat {journal_retention.RETENTION_PATH}"), rendered)
        self.assert_managed(pair)

        # Journald, not Barectl, reclaims space; a documented manual vacuum changes no policy.
        self.native("journalctl --vacuum-time=1s")
        self.assert_managed(pair)

        # A hand edit is outside supported settings, and the kind refuses to overwrite it.
        self.native(
            "printf %s "
            + shlex.quote(rendered + "# hand edit\n")
            + " >"
            + journal_retention.RETENTION_PATH
        )
        with self.shell() as shell:
            evidence = inspect_retention(shell, PreparationInputs(disk_cap="2G", max_age="6months"))
            observation = evidence.observation
            if observation is None:
                self.fail("The hand edit was not reconstructed.")
            self.assertEqual(observation.state, journal_retention.OUTSIDE)
            draft = review_retention(evidence, PreparationInputs(disk_cap="2G", max_age="6months"))
        self.assertFalse(draft.eligible)
        self.assertTrue(
            any("outside supported settings" in refusal for refusal in draft.refusals),
            draft.refusals,
        )

        # Restoring the exact managed file makes it managed again.
        self.native(
            "printf %s "
            + shlex.quote(rendered)
            + " >"
            + journal_retention.RETENTION_PATH
            + "; chmod 0644 "
            + journal_retention.RETENTION_PATH
        )
        self.assert_managed(pair)

        # Review a change while managed, then let a later drop-in override it. The body
        # refuses before writing and the reviewed file stays byte-identical.
        before = self.native(f"sha256sum {journal_retention.RETENTION_PATH}").split()[0]
        with self.shell() as shell:
            draft = engine._planned(
                shell,
                review_retention(
                    inspect_retention(shell, PreparationInputs(disk_cap="2G", max_age="6months")),
                    PreparationInputs(disk_cap="2G", max_age="6months"),
                ),
            )
            self.assertTrue(draft.eligible, draft.refusals)
            self.native(
                "printf %s "
                + shlex.quote("[Journal]\nSystemMaxUse=4G\n")
                + " >"
                + LATER_DROP_IN
                + "; chmod 0644 "
                + LATER_DROP_IN
            )
            with self.shell() as fresh:
                observed = collect(fresh, sites=False).journal_retention
            if observed is None:
                self.fail("The later drop-in was not reconstructed.")
            self.assertEqual(observed.state, journal_retention.OUTSIDE, observed.reason)
            self.assertIn("later configuration overrides", observed.reason)
            submitted = submit_draft(self, shell, SET_JOURNAL_RETENTION, draft)
            self.assertFalse(submitted.no_changes)
            wait_result(self, submitted, expected="refused", reason="precondition")
        self.assertEqual(
            self.native(f"sha256sum {journal_retention.RETENTION_PATH}").split()[0], before
        )

        # Removing the later drop-in leaves the managed file, and a fresh read with no
        # stored snapshot reconstructs the same state.
        self.native(f"rm -f {LATER_DROP_IN}; systemctl restart systemd-journald.service")
        with self.shell() as shell:
            observed = collect(shell, sites=False).journal_retention
        if observed is None:
            self.fail("The fresh read did not reconstruct the retention setting.")
        self.assertEqual(observed.state, journal_retention.MANAGED)
        self.assertEqual((observed.disk_cap, observed.max_age), pair)

    def assert_managed(self, pair: tuple[str, str]) -> None:
        with self.shell() as shell:
            observed = collect(shell, sites=False).journal_retention
        if observed is None:
            self.fail("The fresh read did not reconstruct the retention setting.")
        self.assertEqual(observed.state, journal_retention.MANAGED, observed.reason)
        self.assertEqual((observed.disk_cap, observed.max_age), pair)
