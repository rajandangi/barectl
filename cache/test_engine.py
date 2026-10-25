"""The Valkey install's review, native body and server Settings section.

The review is pure, so most of it is proved without a database or an SSH connection; the
page tests drive the one prepare action. A real install is proved natively by
``disposable/test_cache.py``.
"""

from dataclasses import replace
from typing import cast, override
from unittest import mock

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from databases.packages import PackageAction, Simulation, Transition, guard
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, WebStackComponent
from discovery.snapshot import (
    Observation,
    Package,
    ServiceUnit,
    WebStackComponentObservation,
    save_snapshot,
)
from operations.consent import Scope, consent_of
from operations.engine import BodyContext, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import Consent
from operations.services import read_changes
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from . import engine, observation

VERSION = "9.0.4-0ubuntu0.2"
DIGEST = "b" * 64
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
DPKG_VERSION = "1.23.0"


def transition(
    action: str,
    package: str,
    version: str,
    *,
    previous: str = "",
    arch: str = "amd64",
    origins: tuple[str, ...] = ("resolute-updates",),
) -> Transition:
    return Transition(action, package, previous, version, arch, origins)


def valkey_simulation(*extra: Transition) -> Simulation:
    return Simulation(
        (
            transition("Inst", "valkey-server", VERSION),
            transition("Conf", "valkey-server", VERSION),
            transition("Inst", "valkey-tools", VERSION),
            transition("Conf", "valkey-tools", VERSION),
            *extra,
        ),
        (),
        2_758_000,
        8_500_000,
    )


def valkey_observation(
    version: str = VERSION,
    *,
    masked: bool = True,
    inactive: bool = True,
    managed: bool = True,
    deviations: tuple[str, ...] = (),
) -> observation.ValkeyObservation:
    return observation.ValkeyObservation(
        version,
        (Package("valkey-server", version), Package("valkey-tools", version)),
        (
            ServiceUnit(
                observation.UNIT,
                "masked" if masked else "loaded",
                "inactive" if inactive else "active",
                "dead" if inactive else "running",
                "masked" if masked else "enabled",
            ),
        ),
        managed,
        deviations,
    )


def component(
    version: str = "", *, managed: bool = True, deviations: tuple[str, ...] = ()
) -> WebStackComponentObservation:
    packages = (
        (Package("valkey-server", version), Package("valkey-tools", version)) if version else ()
    )
    units = (
        (ServiceUnit(observation.UNIT, "masked", "inactive", "dead", "masked"),) if version else ()
    )
    return WebStackComponentObservation(
        WebStackComponent.VALKEY,
        Observation(
            ObservationOutcome.OBSERVED if packages else ObservationOutcome.ABSENT,
            ("dpkg-query",),
            "",
            packages,
        ),
        Observation(ObservationOutcome.OBSERVED, ("systemctl",), "", units),
        managed=managed,
        deviations=deviations,
    )


def evidence(
    *,
    installed: observation.ValkeyObservation | None = None,
    components: tuple[WebStackComponentObservation, ...] = (),
    simulation: Simulation | None = None,
    simulation_error: str = "",
    held: tuple[str, ...] = (),
    standing: str = Standing.TARGET_STACK.value,
) -> engine.ValkeyEvidence:
    return engine.ValkeyEvidence(
        standing=standing,
        machine="x86_64",
        deb_arch="amd64",
        boot_id=BOOT,
        uptime_centiseconds=100,
        precondition_digest=DIGEST,
        apt="apt 3.2.0 (amd64)",
        dpkg=f"Debian 'dpkg' package management program version {DPKG_VERSION} (amd64).",
        systemd="systemd 259 (259.5-0ubuntu3.4)",
        held=held,
        disk_bytes=10 * 1024**3,
        memory_kib=2 * 1024**2,
        installed=installed,
        outside=observation.outside_supported(
            replace(COLLECTED, components=(*COLLECTED.components, *components))
        ),
        simulation=simulation,
        simulation_error=simulation_error,
        download_bytes=simulation.download_bytes if simulation is not None else None,
        installed_bytes=simulation.installed_bytes if simulation is not None else None,
    )


def target_snapshot(server: Server, *components: WebStackComponentObservation) -> None:
    collected = replace(
        COLLECTED,
        components=tuple(components),
        sites=Observation(ObservationOutcome.OBSERVED, ("/etc/caddy/sites",), "", ()),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())


class InstallReviewTests(ControllerConfigTestCase):
    def review(self, value: engine.ValkeyEvidence) -> ReviewDraft:
        return engine.review(value, PreparationInputs())

    def test_a_fresh_install_is_server_scoped_and_names_package_version_and_size(self) -> None:
        draft = self.review(evidence(simulation=valkey_simulation()))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SERVER])
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertEqual(draft.document["engine_version"], VERSION)
        self.assertEqual(draft.document["download_bytes"], 2_758_000)
        self.assertIn(f"valkey-server {VERSION}", str(draft.effects[0].text))
        self.assertIn("2.8 MB", str(draft.effects[0].text))
        details = cast(list[dict[str, str]], draft.document["details"])
        self.assertIn(
            {"label": "Package transaction", "value": f"valkey-server {VERSION}"},
            details,
        )
        self.assertIn({"label": "Download size", "value": "2.8 MB"}, details)
        self.assertEqual(draft.stages, engine.STAGES)
        self.assertIn("6379", " ".join(draft.postconditions))

    def test_an_installed_masked_valkey_proposes_no_changes(self) -> None:
        draft = self.review(evidence(installed=valkey_observation(), simulation=Simulation((), ())))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(consent_of(draft.effects), Consent.READ)
        self.assertIn("already installed", str(draft.document["note"]))
        self.assertIn("masked", str(draft.document["note"]))

    def test_an_installed_valkey_that_still_runs_is_refused(self) -> None:
        draft = self.review(evidence(installed=valkey_observation(masked=False, inactive=False)))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("not stopped and masked" in reason for reason in draft.refusals))

    def test_an_upgrade_in_the_simulation_is_refused(self) -> None:
        simulation = Simulation(
            (
                transition("Inst", "valkey-server", VERSION, previous="9.0.2-0ubuntu1"),
                transition("Conf", "valkey-server", VERSION, previous="9.0.2-0ubuntu1"),
            ),
            (),
        )
        draft = self.review(evidence(simulation=simulation))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("change valkey-server" in reason for reason in draft.refusals))

    def test_a_held_package_is_refused(self) -> None:
        draft = self.review(evidence(simulation=valkey_simulation(), held=("valkey-server",)))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("apt-mark hold" in reason for reason in draft.refusals))

    def test_apt_problems_are_refused(self) -> None:
        draft = self.review(evidence(simulation=Simulation((), ("APT reported an error.",))))
        self.assertFalse(draft.eligible)
        self.assertIn("APT reported an error.", draft.refusals)

    def test_a_missing_foundation_is_refused(self) -> None:
        draft = self.review(
            evidence(simulation=valkey_simulation(), standing=Standing.NOT_MANAGEABLE.value)
        )
        self.assertFalse(draft.eligible)
        self.assertTrue(any("foundation" in reason for reason in draft.refusals))

    def test_an_outside_package_is_refused(self) -> None:
        draft = self.review(
            evidence(
                components=(
                    component(
                        managed=False,
                        deviations=(
                            "valkey is installed but is not one of the Valkey profile's packages.",
                        ),
                    ),
                )
            )
        )
        self.assertFalse(draft.eligible)
        self.assertTrue(any("Valkey profile" in reason for reason in draft.refusals))

    def test_a_review_without_a_download_size_is_refused(self) -> None:
        simulation = Simulation(
            (
                transition("Inst", "valkey-server", VERSION),
                transition("Conf", "valkey-server", VERSION),
            ),
            (),
        )
        draft = self.review(evidence(simulation=simulation))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("download size" in reason for reason in draft.refusals))

    def test_the_body_rebuilds_the_guard_from_the_reviewed_actions(self) -> None:
        draft = self.review(evidence(simulation=valkey_simulation()))
        body = engine.body(draft.document, BodyContext("", "", 0))
        arguments = list(body.arguments)
        self.assertEqual(body.source, engine.BODY_BYTES)
        self.assertEqual(arguments[1], f"valkey-server={VERSION}")
        self.assertEqual(arguments[3], "valkey-server")
        self.assertEqual(arguments[4], VERSION)
        actions = (
            PackageAction(True, "valkey-server", VERSION, "amd64"),
            PackageAction(False, "valkey-server", VERSION, "amd64"),
            PackageAction(True, "valkey-tools", VERSION, "amd64"),
            PackageAction(False, "valkey-tools", VERSION, "amd64"),
        )
        self.assertEqual(arguments[2], guard(actions))

    def test_the_assembled_body_is_the_checked_in_script(self) -> None:
        import importlib.resources

        self.assertEqual(
            engine.BODY_BYTES,
            importlib.resources.files("cache.bodies")
            .joinpath("install.sh")
            .read_text()
            .replace("# VALKEY_FUNCTIONS", observation.body_functions())
            .rstrip("\n")
            .encode(),
        )
        self.assertFalse(engine.BODY_BYTES.endswith(b"\n"))
        self.assertIn(b"valkey_mask", engine.BODY_BYTES)
        self.assertIn(b"valkey_recover", engine.BODY_BYTES)
        self.assertIn(b"barectl-restarted", engine.BODY_BYTES)

    def test_a_review_without_a_transaction_is_not_a_body(self) -> None:
        draft = self.review(evidence(installed=valkey_observation()))
        with self.assertRaises(ValueError):
            engine.body(draft.document, BodyContext("", "", 0))


class ObjectCacheSettingPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_changes", "change_site", "change_shared")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Cache", ssh_alias="cache.example.com")

    def test_the_panel_offers_valkey_and_queues_a_review(self) -> None:
        target_snapshot(self.server)
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(response, "Object cache (Valkey)")
        self.assertContains(response, "No object cache is installed.")
        self.assertContains(response, "Install Valkey")
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            queued = self.client.post(
                f"/servers/{self.server.pk}/settings/object-cache/prepare/",
                {"kind": engine.SLUG},
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(queued, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1})

    def test_the_panel_names_the_installed_version(self) -> None:
        target_snapshot(self.server, component(VERSION))
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(response, VERSION)
        self.assertContains(response, "no shared cache is running")
        self.assertNotContains(response, "Install Valkey")

    def test_the_panel_names_an_outside_setting(self) -> None:
        target_snapshot(
            self.server,
            component(
                version="",
                managed=False,
                deviations=(
                    "valkey is installed but is not one of the Valkey profile's packages.",
                ),
            ),
        )
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(response, "Outside supported settings")

    def test_a_site_operator_is_refused_in_the_page_and_on_a_direct_post(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_shared"))
        target_snapshot(self.server)
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertNotContains(response, "Install Valkey")
        refused = self.client.post(
            f"/servers/{self.server.pk}/settings/object-cache/prepare/",
            {"kind": engine.SLUG},
        )
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_an_unknown_change_is_refused(self) -> None:
        target_snapshot(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/settings/object-cache/prepare/",
            {"kind": "install_something"},
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/settings/")
        self.assertEqual(read_changes(self.server).rows, [])


class InstallKindRegistrationTests(ControllerConfigTestCase):
    def test_the_kind_is_registered_and_refresh_discovery(self) -> None:
        from operations.engine import kind_of

        kind = kind_of(engine.SLUG)
        if kind is None:
            self.fail("Install Valkey is not registered.")
        self.assertEqual(kind.label, "Install Valkey")
        self.assertTrue(kind.refresh_discovery)
        self.assertEqual(kind.input_choices, ())


class CachePrerequisiteTests(ControllerConfigTestCase):
    def test_a_site_screen_links_to_the_server_install_until_valkey_is_installed(self) -> None:
        from cache.presentation import prerequisite

        server = Server.objects.create(name="Cache", ssh_alias="cache.example.com")
        missing = prerequisite(replace(COLLECTED, components=()), server=server.pk)
        if missing is None:
            self.fail("A server without Valkey has no prerequisite.")
        self.assertEqual(missing.action, "Install Valkey")
        self.assertEqual(missing.url, f"/servers/{server.pk}/settings/object-cache/prepare/")
        self.assertIn("Server Settings", missing.message)

        installed = replace(
            COLLECTED,
            components=(
                *COLLECTED.components,
                component(VERSION),
            ),
        )
        self.assertIsNone(prerequisite(installed, server=server.pk))
