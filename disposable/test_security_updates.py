"""Check for and install exact Ubuntu updates (Phase E #304).

docs/quality.md#native-layer, docs/security-native-design.md. The scenario uses the lane's
dated snapshot archive: it installs the release pocket's OpenSSL and then upgrades it to the
snapshot's security version through the product's own reviewed change. It also proves a
stale review, an unreviewed dependency, a hold placed after review and a modified conffile
refuse before dpkg changes anything.
"""

import shlex
from typing import cast, override

from django.test import tag

from discovery.ssh import RemoteShell
from operations.engine import ChangeKind, ReviewDraft
from operations.inputs import PreparationInputs

from . import mirror
from .change_testing import apply_change, submit_draft, wait_result
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

RELEASE_OPENSSL = "3.5.5-1ubuntu3"
SECURITY_OPENSSL = "3.5.5-1ubuntu3.7"
OPENS = ("openssl", "libssl3t64")
CONFFILE = "/etc/ssl/openssl.cnf"


def write(test: ScenarioTestCase, shell: RemoteShell, path: str, content: str) -> None:
    result = shell.run(f"install -D -m 0644 /dev/stdin {shlex.quote(path)}", stdin=content.encode())
    test.assertEqual(result.exit_status, 0, result.stdout)


@tag(SCENARIO_TAG)
class SecurityUpdates(ScenarioTestCase):
    layer = "L2"
    exclusive = True
    prefix = "supd"
    records: tuple[str, ...] = ()

    def test_1_check_for_updates_refreshes_the_lists_under_the_lock(self) -> None:
        from security.observation import collect
        from security.updates import CHECK_FOR_UPDATES

        with self.shell() as shell:
            self._router(shell)
        self.native("find /var/lib/apt/lists -maxdepth 1 -type f -delete")
        apply_change(self, CHECK_FOR_UPDATES, PreparationInputs(), timeout=120)
        with self.shell() as shell:
            read = collect(shell)
        if not read.observed or read.value is None:
            self.fail("The refreshed lists were not read back.")
        if not read.value.updates.observed or read.value.updates.value is None:
            self.fail(read.value.updates.warning or "The refreshed lists were not read back.")
        age = read.value.updates.value.list_age_seconds
        self.assertIsNotNone(age)
        self.assertLess(age or 0, 600)

    def test_2_installs_the_release_pocket_package_then_its_security_update(self) -> None:
        from security.updates import INSTALL_UPDATES

        with self.shell() as shell:
            self._holds_except()
            self._release(shell)
            draft = self._draft(shell, INSTALL_UPDATES, PreparationInputs("security"))
            roots = {name for name, _version in cast(list[list[str]], draft.document["roots"])}
        self.assertEqual(roots, set(OPENS))
        apply_change(
            self,
            INSTALL_UPDATES,
            PreparationInputs("security"),
            timeout=120,
        )
        self.assertEqual(self._version("openssl"), SECURITY_OPENSSL)
        self.assertEqual(self.native("dpkg --audit 2>&1").strip(), "")

    def test_3_a_stale_review_refuses_before_dpkg_changes_anything(self) -> None:
        from security.updates import INSTALL_UPDATES

        with self.shell() as shell:
            self._holds_except()
            self._release(shell)
            draft = self._draft(shell, INSTALL_UPDATES, PreparationInputs("security"))
        self.native("touch /var/lib/apt/lists/*")
        with self.shell() as shell:
            submitted = submit_draft(self, shell, INSTALL_UPDATES, draft)
        wait_result(self, submitted, expected="refused", reason="evidence")
        self.assertEqual(self._version("openssl"), RELEASE_OPENSSL)

    def test_4_a_hold_placed_after_review_refuses(self) -> None:
        from security.updates import INSTALL_UPDATES

        with self.shell() as shell:
            self._holds_except()
            self._release(shell)
            draft = self._draft(shell, INSTALL_UPDATES, PreparationInputs("security"))
        self.native("apt-mark hold openssl")
        with self.shell() as shell:
            submitted = submit_draft(self, shell, INSTALL_UPDATES, draft)
        wait_result(self, submitted, expected="refused", reason="updates_hold")
        self.assertEqual(self._version("openssl"), RELEASE_OPENSSL)

    def test_5_a_modified_conffile_refuses_before_dpkg_changes_anything(self) -> None:
        from security.updates import INSTALL_UPDATES

        with self.shell() as shell:
            self._holds_except()
            self._release(shell)
            draft = self._draft(shell, INSTALL_UPDATES, PreparationInputs("security"))
        self.native(f"cp -p {CONFFILE} /tmp/openssl.cnf.before")
        self.native(f"printf '\\n# changed\\n' >> {CONFFILE}")
        try:
            with self.shell() as shell:
                submitted = submit_draft(self, shell, INSTALL_UPDATES, draft)
            wait_result(self, submitted, expected="refused", reason="updates_conffile")
        finally:
            self.native(f"cp -p /tmp/openssl.cnf.before {CONFFILE}; rm -f /tmp/openssl.cnf.before")
        self.assertEqual(self._version("openssl"), RELEASE_OPENSSL)

    def test_6_an_unreviewed_dependency_refuses(self) -> None:
        from security.updates import INSTALL_UPDATES

        with self.shell() as shell:
            self._holds_except()
            self._release(shell)
            draft = self._draft(shell, INSTALL_UPDATES, PreparationInputs("security"))
        actions = cast(list[list[object]], draft.document["actions"])
        document = {
            **draft.document,
            "actions": [action for action in actions if action[1] != "libssl3t64"],
            "packages": ["openssl"],
            "requested": f"openssl={SECURITY_OPENSSL}",
            "roots": [["openssl", SECURITY_OPENSSL]],
        }
        tampered = ReviewDraft(
            draft.kind,
            draft.intent,
            effects=draft.effects,
            stages=draft.stages,
            postconditions=draft.postconditions,
            boot_id=draft.boot_id,
            uptime_centiseconds=draft.uptime_centiseconds,
            sites_read=draft.sites_read,
            current_sites=draft.current_sites,
            document=document,
        )
        with self.shell() as shell:
            submitted = submit_draft(self, shell, INSTALL_UPDATES, tampered)
        wait_result(self, submitted, expected="refused", reason="updates_transaction")
        self.assertEqual(self._version("openssl"), RELEASE_OPENSSL)

    def test_7_a_lost_response_is_reconciled_from_native_evidence(self) -> None:
        from security.updates import INSTALL_UPDATES

        with self.shell() as shell:
            self._holds_except()
            self._release(shell)
            draft = self._draft(shell, INSTALL_UPDATES, PreparationInputs("security"))
        with self.shell() as shell:
            submitted = submit_draft(self, shell, INSTALL_UPDATES, draft, acknowledge=False)
        wait_result(self, submitted, timeout=120)
        self.assertEqual(self._version("openssl"), SECURITY_OPENSSL)
        self.assertIn(
            'barectl-result {"class":"succeeded"}',
            self.native(f"journalctl -u {submitted.unit} --no-pager -o cat"),
        )

    def _router(self, shell: RemoteShell) -> None:
        write(self, shell, "/etc/apt/sources.list.d/barectl-fixture.sources", mirror.apt_sources())
        write(
            self,
            shell,
            "/etc/apt/apt.conf.d/99barectl-fixture",
            'Acquire::By-Hash "no";\nAcquire::Languages "none";\n',
        )
        self.assertEqual(shell.run("rm -f /etc/apt/sources.list.d/ubuntu.sources").exit_status, 0)
        update = shell.run("apt-get update 2>&1")
        self.assertEqual(update.exit_status, 0, update.stdout)

    def _release(self, shell: RemoteShell) -> None:
        update = shell.run("apt-get update 2>&1")
        self.assertEqual(update.exit_status, 0, update.stdout)
        policy = shell.run("apt-cache policy openssl 2>&1").stdout
        self.assertIn(RELEASE_OPENSSL, policy)
        self._downgrade()

    def _downgrade(self) -> None:
        self.native(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "
            f"openssl={RELEASE_OPENSSL} libssl3t64={RELEASE_OPENSSL}"
        )
        self.assertEqual(self._version("openssl"), RELEASE_OPENSSL)
        self.assertNotIn("openssl", self.native("apt-mark showhold").split())
        pending = self.native(
            "apt-get -s -o APT::Get::Show-Versions=1 upgrade --with-new-pkgs 2>&1 | head -40"
        )
        self.assertIn("openssl", pending)

    def _holds_except(self) -> None:
        pending = self.native(
            "apt-get -s -o APT::Get::Show-Versions=1 upgrade --with-new-pkgs "
            "| awk '/^Inst / {print $2}' | LC_ALL=C sort -u"
        ).split()
        for name in pending:
            if name not in OPENS:
                self.native(f"apt-mark hold {shlex.quote(name)}")

    def _draft(
        self, shell: RemoteShell, kind: ChangeKind, inputs: PreparationInputs
    ) -> ReviewDraft:
        from security.updates import UpdatesEvidence

        evidence = kind.inspect(shell, inputs)
        if isinstance(evidence, UpdatesEvidence):
            self.assertIsNotNone(evidence.state, evidence.update_warning)
        draft = kind.review(evidence, inputs)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.effects, draft.document.get("note"))
        return draft

    def _version(self, name: str) -> str:
        return self.native(
            f"dpkg-query -W -f='${{Version}}' {shlex.quote(name)} 2>/dev/null"
        ).strip()

    @override
    def tearDown(self) -> None:
        self.native(
            "apt-mark showhold | while read -r name; do "
            '[ -n "$name" ] && apt-mark unhold "$name"; done'
        )
        super().tearDown()
