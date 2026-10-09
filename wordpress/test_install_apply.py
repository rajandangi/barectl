"""Applying a reviewed WordPress installation through requests and the worker
(docs/wordpress.md#applying-an-installation), against a simulated server."""

from typing import override
from unittest import mock

from bootstrap import apply as bootstrap_apply
from bootstrap.fakes import NativeSystemd
from bootstrap.models import ApplyRun, ConfigurationPlan

from .install_testing import PREPARE, InstallTestCase

PERMISSIONS = (*PREPARE, "install_wordpress")


class ApplyTests(InstallTestCase):
    systemd: NativeSystemd

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    def apply(self, plan: ConfigurationPlan) -> ApplyRun:
        self.sign_in_as(*PERMISSIONS)
        self.systemd.answer(self.remote)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run

    def test_explore(self) -> None:
        plan = self.reviewed()
        run = self.apply(plan)
        from . import install_apply, install_native
        from .models import PlanWordpressInstall

        row = PlanWordpressInstall.objects.get(plan=plan)
        print("pinned", install_apply._pinned(row))
        ev = install_apply._evidence(plan)
        print(ev)
        text, body = install_native.staged_payload(
            run.unit_name, run.boot_id, run.admission_deadline_centiseconds, row, ev, run.release
        )
        print("payload", len(text), "body", len(body), "row", row.payload_bytes)
        import pathlib

        pathlib.Path("/tmp/body248.sh").write_text(body)
        pathlib.Path("/tmp/payload248.sh").write_text(text)
        pathlib.Path("/tmp/row248.txt").write_text(
            repr({f.name: getattr(row, f.name) for f in row._meta.concrete_fields})
        )
        pathlib.Path("/tmp/ev248.txt").write_text(repr(ev))
        print(len(self.systemd.submissions[0]) if self.systemd.submissions else None)
