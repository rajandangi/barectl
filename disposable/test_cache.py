"""Valkey installed and masked by the product's own reviewed change (#391).

docs/quality.md#native-layer. The lane server reaches only its lane's pinned snapshot. The
class starts from L1, creates one site through the product so a PHP master and a site proxy
are running, then proves the transaction's ``daemon-reload`` recovery on those real units
(issue #428).
"""

import shlex
from typing import cast

from django.test import tag

from discovery.observations import collect
from discovery.ssh import RemoteShell
from operations.engine import ChangeKind, ReviewDraft
from operations.inputs import PreparationInputs

from . import mirror
from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

STATE = "valkey-installed-26.04"
PACKAGE = "valkey-server"
MIRRORED_VERSION = "9.0.4"
SITE = "scachebase"
DOMAIN = "scachebase.example.com"
RUNNING_UNITS = (
    "php-fpm@php84.service",
    "php-fpm@php85.service",
    f"haproxy-site@{SITE}.service",
    f"php-fpm-site-php84@{SITE}.service",
)


def write(test: ScenarioTestCase, shell: RemoteShell, path: str, content: str) -> None:
    result = shell.run(f"install -D -m 0644 /dev/stdin {shlex.quote(path)}", stdin=content.encode())
    test.assertEqual(result.exit_status, 0, result.stdout)


class ValkeyCase(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "scache"

    def router(self, shell: RemoteShell) -> None:
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

    def review(self, shell: RemoteShell, kind: ChangeKind) -> ReviewDraft:
        inputs = PreparationInputs()
        return kind.review(kind.inspect(shell, inputs), inputs)

    def invocations(self) -> dict[str, str]:
        """The invocation of each running unit the package transaction will unbind."""
        running: dict[str, str] = {}
        for unit in RUNNING_UNITS:
            state = self.native(f"systemctl is-active {unit} || true").strip()
            if state == "active":
                running[unit] = self.native(
                    f"systemctl show -p InvocationID --value {unit}"
                ).strip()
        return running


@tag(SCENARIO_TAG)
class ValkeyInstall(ValkeyCase):
    records: tuple[str, ...] = (STATE,)

    def test_1_installs_masks_and_keeps_running_units_verifiable(self) -> None:
        from cache import engine as kinds
        from sites import change as site_change

        apply_change(
            self,
            site_change.CREATE_SITE,
            PreparationInputs("php84", SITE, (DOMAIN,)),
            timeout=60,
        )
        with self.shell() as shell:
            prepared = collect(shell)
        before_site = {site.identifier: site for site in prepared.sites.value}[SITE]
        self.assertEqual(before_site.state.value, "managed", before_site.missing)
        before = self.invocations()
        self.assertGreaterEqual(len(before), 3, before)
        with self.shell() as shell:
            self.router(shell)
            draft = self.review(shell, kinds.INSTALL)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertEqual([effect.scope.value for effect in draft.effects], ["server"])
            details = cast(list[dict[str, str]], draft.document["details"])
            listed = {item["label"]: item["value"] for item in details}
            self.assertTrue(
                listed["Package transaction"].startswith(f"{PACKAGE} {MIRRORED_VERSION}")
            )
            self.assertNotIn(listed["Download size"], {"", "Not reported."})
            self.assertGreater(cast(int, draft.document["download_bytes"]), 0)
        apply_change(self, kinds.INSTALL, PreparationInputs(), timeout=120)

        self.assertEqual(
            self.native(f"dpkg-query -W -f='${{Version}}' {PACKAGE}").strip(),
            cast(list[list[str]], draft.document["roots"])[0][1],
        )
        for property_name, expected in (
            ("LoadState", "masked"),
            ("UnitFileState", "masked"),
            ("ActiveState", "inactive"),
        ):
            with self.subTest(property=property_name):
                self.assertEqual(
                    self.native(
                        f"systemctl show -p {property_name} --value {PACKAGE}.service"
                    ).strip(),
                    expected,
                )
        self.assertEqual(self.native("ss -Hltn 'sport = :6379'").strip(), "")

        # #428: the package transaction's daemon-reload unbinds running units, so the change
        # restarts exactly the ones it affected and discovery verifies them again.
        after = self.invocations()
        self.assertEqual(set(after), set(before), after)
        for unit, invocation in before.items():
            with self.subTest(unit=unit):
                self.assertNotEqual(after[unit], invocation)

        served = self.native(
            "curl --fail --silent -H 'Host: scachebase.example.com' http://127.0.0.1/"
        )
        self.assertIn(SITE, served)

        with self.shell() as shell:
            # The transcript holds the installed state's review and full discovery, so a
            # fresh controller replays the same reads the fast layer proves.
            self.review(shell, kinds.INSTALL)
            observed = collect(shell)
            self.checkpoint(STATE, shell)
        sites = {site.identifier: site for site in observed.sites.value}
        if SITE not in sites:
            reasons = observed.standing.reasons if observed.standing is not None else ()
            self.fail("The prepared site was not read after the install: " + "; ".join(reasons))
        self.assertEqual(sites[SITE].state.value, "managed", sites[SITE].missing)
        problems = {
            runtime.entry: runtime.problem for runtime in observed.runtimes if runtime.problem
        }
        self.assertEqual(problems, {})
        from cache import observation

        current = observation.installed(observed)
        if current is None:
            self.fail("Discovery does not report Valkey as installed.")
        self.assertTrue(current.masked)
        self.assertTrue(current.inactive)

    def test_2_a_second_review_proposes_no_changes(self) -> None:
        from cache import engine as kinds

        with self.shell() as shell:
            draft = self.review(shell, kinds.INSTALL)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.effects)
        self.assertIn("already installed", str(draft.document["note"]))

    def test_3_a_fresh_controller_reconstructs_installed_masked_valkey(self) -> None:
        from cache import observation

        with self.shell() as shell:
            observed = collect(shell, sites=False)
        current = observation.installed(observed)
        if current is None:
            self.fail("A fresh controller does not reconstruct Valkey.")
        self.assertTrue(current.version.startswith(MIRRORED_VERSION))
        self.assertTrue(current.managed)
        self.assertTrue(current.masked)
        self.assertTrue(current.inactive)
