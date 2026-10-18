"""The database engine change's review, native body and Database setting.

The review is pure, so most of it is proved without a database or an SSH connection; the
page tests drive the one prepare action. A real install is proved natively by
``disposable/test_database_engine.py``.
"""

from dataclasses import replace
from typing import cast, override
from unittest import mock

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import (
    CollectedSnapshot,
    Observation,
    Package,
    ServiceUnit,
    WebStackComponentObservation,
    save_snapshot,
)
from operations.consent import Scope
from operations.engine import BodyContext, ReviewDraft
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.services import read_changes
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from . import engine, observation
from .packages import PackageAction, Simulation, Transition, guard

MARIADB_VERSION = "1:11.8.6-5ubuntu0.1"
POSTGRES_VERSION = "18.6-0ubuntu0.26.04.1"
DIGEST = "a" * 64
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
DPKG_VERSION = "1.23.0"


def engine_observation(
    engine_name: str,
    version: str = "",
    *,
    managed: bool = True,
    deviations: tuple[str, ...] = (),
) -> observation.EngineObservation:
    spec = observation.specs()[engine_name]
    packages = (Package(spec.versioned, version),) if version else ()
    return observation.EngineObservation(
        engine_name,
        spec.label,
        version,
        packages,
        (ServiceUnit(spec.units[0], "loaded", "active", "running", "enabled"),),
        managed,
        deviations,
    )


def component(
    engine_name: str,
    version: str = "",
    *,
    managed: bool = True,
    names: tuple[str, ...] = (),
    deviations: tuple[str, ...] = (),
) -> WebStackComponentObservation:
    spec = observation.specs()[engine_name]
    package_names = names or ((spec.versioned,) if version else ())
    return WebStackComponentObservation(
        spec.component,
        Observation(
            ObservationOutcome.OBSERVED if package_names else ObservationOutcome.ABSENT,
            ("dpkg-query",),
            "",
            tuple(Package(name, version or "1.0") for name in package_names),
        ),
        Observation(ObservationOutcome.OBSERVED, ("systemctl",), "", ()),
        managed=managed,
        deviations=deviations,
    )


def collected_with(*components: WebStackComponentObservation) -> CollectedSnapshot:
    return replace(COLLECTED, components=tuple(components))


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


def mariadb_simulation(*extra: Transition) -> Simulation:
    servers = (
        transition("Inst", "mariadb-server", MARIADB_VERSION),
        transition("Conf", "mariadb-server", MARIADB_VERSION),
        transition("Inst", "mariadb-server-core", MARIADB_VERSION),
        transition("Conf", "mariadb-server-core", MARIADB_VERSION),
    )
    return Simulation((*servers, *extra), ())


def postgres_simulation() -> Simulation:
    return Simulation(
        (
            transition("Inst", "postgresql", "18+290ubuntu1"),
            transition("Conf", "postgresql", "18+290ubuntu1"),
            transition("Inst", "postgresql-18", POSTGRES_VERSION),
            transition("Conf", "postgresql-18", POSTGRES_VERSION),
        ),
        (),
    )


def evidence(
    engine_name: str = "mariadb",
    *,
    installed: tuple[observation.EngineObservation, ...] = (),
    components: tuple[WebStackComponentObservation, ...] = (),
    simulation: Simulation | None = None,
    simulation_error: str = "",
    git: bool = False,
    git_installed: bool = False,
    held: tuple[str, ...] = (),
    standing: str = Standing.TARGET_STACK.value,
) -> engine.EngineEvidence:
    return engine.EngineEvidence(
        engine=engine_name,
        git=git,
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
        git_installed=git_installed,
        installed=installed,
        outside=observation.outside_supported_engines(collected_with(*components)),
        simulation=simulation,
        simulation_error=simulation_error,
        usage=(),
        usage_readable=True,
    )


class EngineReviewTests(ControllerConfigTestCase):
    def review(self, value: engine.EngineEvidence) -> ReviewDraft:
        return engine.review(value, PreparationInputs(value.engine, git=value.git))

    def test_a_fresh_install_is_server_scoped_and_names_every_package(self) -> None:
        draft = self.review(evidence(simulation=mariadb_simulation()))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(len(draft.effects), 1)
        self.assertEqual(draft.effects[0].scope, Scope.SERVER)
        self.assertIn("mariadb-server", draft.effects[0].text)
        self.assertEqual(draft.document["engine"], "mariadb")
        self.assertEqual(draft.document["engine_version"], MARIADB_VERSION)
        self.assertEqual(draft.document["roots"], [["mariadb-server", MARIADB_VERSION]])
        self.assertEqual(
            draft.document["packages"],
            [
                ["mariadb-server", MARIADB_VERSION, "amd64"],
                ["mariadb-server-core", MARIADB_VERSION, "amd64"],
            ],
        )
        self.assertTrue(draft.document["actions"])

    def test_both_engines_are_outside_supported_settings(self) -> None:
        value = evidence(
            simulation=mariadb_simulation(),
            installed=(
                engine_observation("mariadb", MARIADB_VERSION),
                engine_observation("postgresql", POSTGRES_VERSION),
            ),
            components=(
                component("mariadb", MARIADB_VERSION),
                component("postgresql", POSTGRES_VERSION),
            ),
        )
        draft = self.review(value)
        self.assertFalse(draft.eligible)
        self.assertTrue(any("one database engine" in reason for reason in draft.refusals))
        self.assertFalse(draft.effects)

    def test_a_foreign_version_is_outside_supported_settings(self) -> None:
        deviations = ("mariadb-server-10.11 is installed but is not a supported package.",)
        draft = self.review(
            evidence(
                simulation=mariadb_simulation(),
                installed=(engine_observation("mariadb", managed=False, deviations=deviations),),
                components=(
                    component(
                        "mariadb",
                        managed=False,
                        names=("mariadb-server-10.11",),
                        deviations=deviations,
                    ),
                ),
            )
        )
        self.assertFalse(draft.eligible)
        self.assertIn(deviations[0], draft.refusals)

    def test_a_different_engine_is_refused_while_one_is_installed(self) -> None:
        draft = self.review(
            evidence(
                engine_name="postgresql",
                simulation=postgres_simulation(),
                installed=(engine_observation("mariadb", MARIADB_VERSION),),
                components=(component("mariadb", MARIADB_VERSION),),
            )
        )
        self.assertFalse(draft.eligible)
        self.assertTrue(any("one database engine" in reason for reason in draft.refusals))
        self.assertFalse(draft.effects)

    def test_an_installed_engine_proposes_no_changes(self) -> None:
        draft = self.review(
            evidence(
                installed=(engine_observation("mariadb", MARIADB_VERSION),),
                components=(component("mariadb", MARIADB_VERSION),),
                simulation=Simulation((), ()),
            )
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.effects)
        self.assertIn("already installed", str(draft.document["note"]))

    def test_an_upgrade_in_the_simulation_is_refused(self) -> None:
        simulation = Simulation(
            (
                transition("Inst", "libc6", "2.43", previous="2.42"),
                transition("Conf", "libc6", "2.43", previous="2.42"),
            ),
            (),
        )
        draft = self.review(evidence(simulation=simulation))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("would change" in reason for reason in draft.refusals))

    def test_a_held_package_is_refused(self) -> None:
        draft = self.review(evidence(simulation=mariadb_simulation(), held=("mariadb-server",)))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("apt-mark hold" in reason for reason in draft.refusals))

    def test_apt_problems_are_refused(self) -> None:
        draft = self.review(evidence(simulation=Simulation((), ("APT reported an error.",))))
        self.assertFalse(draft.eligible)
        self.assertIn("APT reported an error.", draft.refusals)

    def test_a_missing_foundation_is_refused(self) -> None:
        draft = self.review(
            evidence(simulation=mariadb_simulation(), standing=Standing.FRESH.value)
        )
        self.assertFalse(draft.eligible)
        self.assertTrue(any("foundation" in reason for reason in draft.refusals))

    def test_git_is_installed_through_the_same_transaction(self) -> None:
        draft = self.review(
            evidence(
                simulation=mariadb_simulation(
                    transition("Inst", "git", "2.53.0-1ubuntu1"),
                    transition("Conf", "git", "2.53.0-1ubuntu1"),
                ),
                git=True,
            )
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(
            draft.document["roots"],
            [["mariadb-server", MARIADB_VERSION], ["git", "2.53.0-1ubuntu1"]],
        )
        body = engine.body(draft.document, BodyContext("u", BOOT, 1))
        self.assertIn("git=2.53.0-1ubuntu1", body.arguments[2])
        self.assertIn("mariadb-server=", body.arguments[2])

    def test_a_review_without_a_transaction_is_not_a_body(self) -> None:
        with self.assertRaises(ValueError):
            engine.body(
                {"version": 1, "body_sha256": engine.BODY_SHA256},
                BodyContext("", "", 0),
            )

    def test_the_body_rebuilds_the_guard_from_the_reviewed_actions(self) -> None:
        draft = self.review(evidence(simulation=mariadb_simulation()))
        body = engine.body(draft.document, BodyContext("u", BOOT, 1))
        self.assertEqual(body.source, engine.BODY_BYTES)
        actions = cast(list[list[object]], draft.document["actions"])
        self.assertEqual(
            body.arguments[3],
            guard(
                tuple(PackageAction(bool(a[0]), str(a[1]), str(a[2]), str(a[3])) for a in actions)
            ),
        )

    def test_the_generated_body_embeds_the_reviewed_digest_and_hardening(self) -> None:
        text = engine.BODY_BYTES.decode()
        self.assertIn(observation.digest_command("mariadb"), text)
        self.assertIn("skip-networking", text)


class RemovalReviewTests(ControllerConfigTestCase):
    def removal(self, *, usage: tuple[str, ...], installed: bool = True) -> ReviewDraft:
        value = engine.RemovalEvidence(
            engine="mariadb",
            standing=Standing.TARGET_STACK.value,
            boot_id=BOOT,
            uptime_centiseconds=100,
            precondition_digest=DIGEST,
            installed=(engine_observation("mariadb", MARIADB_VERSION),) if installed else (),
            usage=usage,
            usage_readable=True,
        )
        return engine.review_removal(value, PreparationInputs("mariadb"))

    def test_removal_is_refused_while_a_database_exists(self) -> None:
        draft = self.removal(usage=("s1alpha",))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("refuses to remove" in reason for reason in draft.refusals))
        self.assertFalse(draft.effects)

    def test_removal_names_its_packages_when_no_database_exists(self) -> None:
        draft = self.removal(usage=())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["packages"], ["mariadb-server"])

    def test_removal_of_an_absent_engine_proposes_no_changes(self) -> None:
        draft = self.removal(usage=(), installed=False)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.effects)
        self.assertIn("not installed", str(draft.document["note"]))


class EngineInputTests(ControllerConfigTestCase):
    def test_the_engine_shape_accepts_git(self) -> None:
        value = decode_inputs(
            {"version": 1, "selection": "mariadb", "git": True},
            engine.ENGINE_CHOICES,
            InputShape.DATABASE_ENGINE,
        )
        self.assertEqual(value, PreparationInputs("mariadb", git=True))
        self.assertEqual(value.document(), {"version": 1, "selection": "mariadb", "git": True})

    def test_the_engine_shape_rejects_an_unknown_engine(self) -> None:
        with self.assertRaises(ValueError):
            decode_inputs(
                {"version": 1, "selection": "mysql"},
                engine.ENGINE_CHOICES,
                InputShape.DATABASE_ENGINE,
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


class DatabaseSettingPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="DB", ssh_alias="db.example.com")

    def test_the_database_panel_offers_both_engines_and_queues_a_review(self) -> None:
        target_snapshot(self.server)
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(response, "Database")
        self.assertContains(response, "No database engine is installed.")
        self.assertContains(response, "Install MariaDB")
        self.assertContains(response, "Install PostgreSQL")
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            queued = self.client.post(
                f"/servers/{self.server.pk}/settings/database/prepare/",
                {"kind": engine.SLUG, "selection": "mariadb"},
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(queued, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "selection": "mariadb"})

    def test_the_panel_names_the_installed_engine_and_its_version(self) -> None:
        target_snapshot(self.server, component("mariadb", MARIADB_VERSION))
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(response, "MariaDB")
        self.assertContains(response, MARIADB_VERSION)
        self.assertContains(response, "Remove MariaDB")
        self.assertNotContains(response, "Install MariaDB")

    def test_the_panel_explains_an_outside_setting(self) -> None:
        target_snapshot(
            self.server,
            replace(
                component("mariadb", MARIADB_VERSION, managed=False),
                deviations=("mariadb-server-10.11 is installed but is not a supported package.",),
            ),
        )
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(response, "Outside supported settings")

    def test_an_unknown_engine_is_refused(self) -> None:
        target_snapshot(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/settings/database/prepare/",
            {"kind": engine.SLUG, "selection": "mysql"},
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/settings/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_viewer_cannot_queue_an_engine_change(self) -> None:
        target_snapshot(self.server)
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/settings/database/prepare/",
            {"kind": engine.SLUG, "selection": "mariadb"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])
