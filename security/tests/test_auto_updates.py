from django.test import SimpleTestCase

from databases.packages import Simulation, Transition
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.inputs import PreparationInputs
from operations.models import Consent
from security.change import SLUG, AutoUpdatesEvidence, body, review
from security.observation import DEFAULT_ALLOWED_ORIGINS, AutoUpdatesState

BOOT_ID = "0123456789abcdef0123456789abcdef"
DIGEST = "a" * 64


def _state(
    *,
    enabled: bool = True,
    list_update_timer: str = "enabled",
    upgrade_timer: str = "enabled",
    automatic_reboot: bool = False,
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_ORIGINS,
    conffile_matches_package: bool | None = True,
    last_upgrade: str = "Packages that were upgraded: openssl",
    newest_log_age: int | None = 3600,
    package_installed: bool = True,
    package_blacklist: tuple[str, ...] = (),
) -> AutoUpdatesState:
    return AutoUpdatesState(
        enabled,
        list_update_timer,
        upgrade_timer,
        automatic_reboot,
        allowed_origins,
        conffile_matches_package,
        last_upgrade,
        newest_log_age,
        package_installed,
        package_blacklist,
    )


def _evidence(
    state: AutoUpdatesState | None = None,
    *,
    simulation: Simulation | None = None,
) -> AutoUpdatesEvidence:
    return AutoUpdatesEvidence(
        state=state or _state(),
        standing="Target stack",
        machine="x86_64",
        deb_arch="amd64",
        boot_id=BOOT_ID,
        uptime_centiseconds=500000,
        apt="apt 3.2.0 (amd64)",
        dpkg="Debian 'dpkg' package management program version 1.23.1 (amd64).",
        systemd="systemd 259 (259-1ubuntu1)",
        held=(),
        installed_version="2.12ubuntu9",
        precondition_digest=DIGEST,
        settings_digest=DIGEST,
        simulation=simulation,
        sites=("alpha", "beta"),
    )


def _simulation() -> Simulation:
    return Simulation(
        (
            Transition(
                "Inst",
                "unattended-upgrades",
                "",
                "2.12ubuntu9",
                "all",
                ("resolute/main",),
            ),
            Transition(
                "Conf",
                "unattended-upgrades",
                "",
                "2.12ubuntu9",
                "all",
                ("resolute/main",),
            ),
        ),
        (),
    )


class AutomaticUpdatesReviewTests(SimpleTestCase):
    def test_a_supported_enabled_setup_needs_no_change(self) -> None:
        draft = review(_evidence(), PreparationInputs("on"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.effects)
        self.assertIn("already on", str(draft.document["note"]))

    def test_turning_updates_on_is_a_shared_server_change_naming_every_site(self) -> None:
        draft = review(_evidence(_state(enabled=False)), PreparationInputs("on"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SERVER])
        self.assertEqual(draft.effects[0].sites, ("alpha", "beta"))
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertEqual(draft.current_sites, ("alpha", "beta"))
        self.assertEqual(draft.sites_read.count("/etc/caddy/sites"), 1)

    def test_customized_origins_refuse_turning_updates_on_and_leave_them_alone(self) -> None:
        state = _state(allowed_origins=("Ubuntu:resolute", "Example:resolute"))
        on = review(_evidence(state), PreparationInputs("on"))
        self.assertFalse(on.eligible)
        self.assertTrue(any("allowed update sources" in reason for reason in on.refusals))
        off = review(_evidence(state), PreparationInputs("off"))
        self.assertTrue(off.eligible, off.refusals)
        self.assertEqual(off.document["origins"], list(state.allowed_origins))

    def test_blacklists_automatic_reboot_and_a_disabled_timer_are_customized(self) -> None:
        for state, reason in (
            (_state(package_blacklist=("linux-",)), "kept out"),
            (_state(automatic_reboot=True), "restart itself"),
            (_state(upgrade_timer="disabled"), "timers is disabled"),
            (_state(conffile_matches_package=False), "settings file was edited"),
        ):
            with self.subTest(reason=reason):
                draft = review(_evidence(state), PreparationInputs("on"))
                self.assertFalse(draft.eligible)
                self.assertTrue(any(reason in item for item in draft.refusals), draft.refusals)

    def test_a_missing_package_is_the_exact_reviewed_transaction(self) -> None:
        state = _state(
            enabled=False,
            package_installed=False,
            allowed_origins=(),
            conffile_matches_package=None,
        )
        draft = review(_evidence(state, simulation=_simulation()), PreparationInputs("on"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.document["install"])
        self.assertEqual(draft.document["roots"], [["unattended-upgrades", "2.12ubuntu9"]])
        actions = draft.document["actions"]
        self.assertIsInstance(actions, list)
        self.assertEqual(len(actions), 2)  # type: ignore[arg-type]
        self.assertEqual(draft.document["origins"], list(DEFAULT_ALLOWED_ORIGINS))
        native = body(draft.document, BodyContext("unit", BOOT_ID, 500000))
        self.assertIn("barectl_package_guard", native.arguments[3])

    def test_the_body_refuses_a_tampered_selection(self) -> None:
        draft = review(_evidence(_state(enabled=False)), PreparationInputs("on"))
        document = dict(draft.document)
        document["state"] = "sideways"
        with self.assertRaises(ValueError):
            body(document, BodyContext("unit", BOOT_ID, 500000))

    def test_the_kind_slug_is_the_one_the_security_page_prepares(self) -> None:
        self.assertEqual(SLUG, "set_automatic_security_updates")
