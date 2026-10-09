"""An installed-site test case with an executing simulated server, for the tests that apply a
reviewed WordPress installation or Finish (docs/wordpress.md#applying-an-installation)."""

import base64
import gzip
import re
from typing import override
from unittest import mock

from bootstrap import apply as bootstrap_apply
from bootstrap.fakes import NativeSystemd
from bootstrap.models import ApplyRun, ConfigurationPlan

from .install_testing import PREPARE, InstallTestCase

INSTALL = (*PREPARE, "install_wordpress")


def staged_body(submission: str) -> str:
    """The reviewed body a submission carries, decoded the way the server decodes it."""
    found = re.search(r"b=\$\(printf %s '\"'\"'([A-Za-z0-9+/=]+)'\"'\"'", submission)
    if found is None:
        raise AssertionError("The submission carries no staged body.")
    return gzip.decompress(base64.b64decode(found[1])).decode()


class ApplyTestCase(InstallTestCase):
    systemd: NativeSystemd

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.systemd.on_submit = self.applied
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    def applied(self) -> None:
        """A successful run leaves the application, as the payload does."""
        self.state.applied = self.systemd.exit_status == 0

    @override
    def assert_read_only(self) -> None:
        """Apply runs change the server; each is submitted once."""

    def apply(
        self, plan: ConfigurationPlan | None = None, *, perms: tuple[str, ...] = INSTALL
    ) -> ApplyRun:
        plan = plan or self.reviewed()
        self.sign_in_as(*perms)
        self.systemd.answer(self.remote)
        self.state.answer(self.remote)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run
