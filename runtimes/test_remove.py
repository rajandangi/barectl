from dataclasses import replace
from typing import override
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import Observation, ObservedSite, SiteAccount, save_snapshot
from operations.consent import consent_of
from operations.engine import BodyContext
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, Consent
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from . import remove
from .catalog import Architecture, Build, load
from .defaults import DefaultsObservation
from .observation import RuntimeObservation

ARCHITECTURE = Architecture.AARCH64
BOOT = "12345678-1234-1234-1234-123456789abc"


def php_path(entry: str) -> str:
    return next(build.path for build in load().offered(ARCHITECTURE) if build.entry == entry)


def build_of(entry: str) -> Build:
    return next(build for build in load().offered(ARCHITECTURE) if build.entry == entry)


def evidence(
    *,
    installed: tuple[str, ...] = ("php84", "php85"),
    sites: tuple[tuple[str, str], ...] = (),
    incomplete: tuple[str, ...] = (),
    default_php: str = "",
    default_problem: str = "",
    sites_outcome: ObservationOutcome = ObservationOutcome.OBSERVED,
) -> remove.RemovalEvidence:
    rows = [
        {
            "entry": entry,
            "path": php_path(entry),
            "generation": f"{entry}-1-link",
        }
        for entry in installed
    ]
    return remove.RemovalEvidence(
        ARCHITECTURE,
        Standing.TARGET_STACK,
        {"boot": BOOT, "uptime": 1000, "digest": "a" * 64, "runtimes": rows},
        DefaultsObservation(
            default_php,
            php_choices=("php84", "php85"),
            node_choices=("nodejs_22", "nodejs_24"),
            php_problem=default_problem,
        ),
        tuple(sorted(identifier for identifier, _ in sites)),
        sites,
        incomplete,
        sites_outcome,
    )


def site(identifier: str = "alpha") -> ObservedSite:
    return ObservedSite(
        identifier,
        (f"{identifier}.example.com",),
        "php84",
        SiteAccount(1001, 1001, f"/var/www/{identifier}", "/usr/sbin/nologin"),
        SiteState.MANAGED,
        ObservationOutcome.OBSERVED,
        file=f"/etc/caddy/sites/{identifier}.caddy",
    )


class RuntimeRemovalReviewTests(SimpleTestCase):
    def test_an_unused_runtime_is_removed_with_shared_consent(self) -> None:
        draft = remove.review(evidence(), PreparationInputs("php85"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        document = draft.document
        self.assertEqual(document["entry"], "php85")
        self.assertEqual(document["path"], php_path("php85"))
        body = remove.body(document, BodyContext("", "", 0))
        self.assertEqual(body.arguments[0], "php85")
        self.assertEqual(body.arguments[2], php_path("php85"))

    def test_a_site_using_the_runtime_refuses_removal(self) -> None:
        draft = remove.review(evidence(sites=(("alpha", "php85"),)), PreparationInputs("php85"))
        self.assertFalse(draft.eligible)
        self.assertIn("alpha", " ".join(draft.refusals))
        self.assertEqual(consent_of(draft.effects), Consent.READ)

    def test_a_server_default_using_the_runtime_refuses_removal(self) -> None:
        draft = remove.review(evidence(default_php="php85"), PreparationInputs("php85"))
        self.assertFalse(draft.eligible)
        self.assertIn("default PHP", " ".join(draft.refusals))

    def test_an_unreadable_default_refuses_removal(self) -> None:
        draft = remove.review(
            evidence(default_problem="The PHP commands are set by the administrator."),
            PreparationInputs("php85"),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("administrator", " ".join(draft.refusals))

    def test_an_incomplete_site_transition_blocks_php_removal(self) -> None:
        draft = remove.review(evidence(incomplete=("alpha",)), PreparationInputs("php85"))
        self.assertFalse(draft.eligible)
        self.assertIn("transition is incomplete", " ".join(draft.refusals))

    def test_an_uninstalled_runtime_proposes_nothing(self) -> None:
        draft = remove.review(evidence(installed=("php84",)), PreparationInputs("php85"))
        self.assertTrue(draft.eligible)
        self.assertTrue(draft.no_changes)
        self.assertIn("not installed", str(draft.document["note"]))

    def test_an_unreadable_site_inventory_refuses_removal(self) -> None:
        draft = remove.review(
            evidence(sites_outcome=ObservationOutcome.INACCESSIBLE), PreparationInputs("php85")
        )
        self.assertFalse(draft.eligible)
        self.assertIn("site inventory", " ".join(draft.refusals))

    def test_body_refuses_a_tampered_build_generation_or_use(self) -> None:
        draft = remove.review(evidence(), PreparationInputs("php85"))
        document = draft.document
        for mutated in (
            {**document, "path": php_path("php84")},
            {**document, "generation": "php84-1-link"},
            {**document, "sites": ["alpha"]},
            {**document, "default": True},
            {**document, "kind": "node"},
        ):
            with self.subTest(mutated=mutated), self.assertRaises(ValueError):
                remove.body(mutated, BodyContext("", "", 0))


class RuntimeRemovalPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Runtimes", ssh_alias="runtimes.example.com")

    def record(self, sites: tuple[ObservedSite, ...]) -> None:
        collected = replace(
            COLLECTED,
            architecture=Observation(ObservationOutcome.OBSERVED, ("uname -m",), "", "aarch64"),
            sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
            standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
            runtimes=tuple(
                RuntimeObservation(
                    entry,
                    php_path(entry),
                    f"{entry}-1-link",
                    build_of(entry).version,
                    (),
                    "active",
                    (),
                    "",
                )
                for entry in ("php84", "php85")
            ),
        )
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(attempt, collected, timezone.now())

    def test_a_used_runtime_explains_itself_and_an_unused_one_queues_removal(self) -> None:
        self.record((site(),))
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            page = self.client.get(f"/servers/{self.server.pk}/stack/?tab=php")
            self.assertContains(page, "Used by 1 site (alpha)")
            self.assertContains(page, "Remove runtime php85")
            response = self.client.post(
                f"/servers/{self.server.pk}/changes/prepare/",
                {"kind": "remove_runtime", "selection": "php85"},
            )
        preparation = ChangePreparation.objects.get()
        self.assertEqual(preparation.kind_slug, "remove_runtime")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php85"})
        self.assertRedirects(response, f"/changes/{preparation.pk}/")
