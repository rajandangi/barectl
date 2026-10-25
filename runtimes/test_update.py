import base64
import gzip
import json
from dataclasses import replace
from typing import cast, override
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import (
    Observation,
    ObservedSite,
    SiteAccount,
    save_snapshot,
)
from operations.engine import BodyContext
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.bodies.php_runtime import PHPState

from . import update
from .catalog import Architecture, Build, Catalog, load
from .observation import RuntimeObservation
from .presentation import shown_runtimes, shown_updates
from .updates import updates as detect

ARCHITECTURE = Architecture.AARCH64
BOOT = "12345678-1234-1234-1234-123456789abc"


def catalog_with_old_build(entry: str = "php84") -> tuple[Catalog, Build, Build]:
    real = load()
    current = next(build for build in real.offered(ARCHITECTURE) if build.entry == entry)
    old = replace(
        current,
        path="/nix/store/" + "a" * 32 + f"-{entry}-previous",
        version="8.4.20" if entry == "php84" else "8.5.10",
        retired=True,
    )
    return replace(real, builds=(*real.builds, old)), current, old


def with_old_tool(catalog: Catalog, entry: str) -> tuple[Catalog, Build, Build]:
    current = next(build for build in catalog.offered(ARCHITECTURE) if build.entry == entry)
    old = replace(
        current,
        path="/nix/store/" + "c" * 32 + f"-{entry}-previous",
        version=current.version,
        retired=True,
    )
    return replace(catalog, builds=(*catalog.builds, old)), current, old


def tool_path(entry: str) -> str:
    return next(build.path for build in load().offered(ARCHITECTURE) if build.entry == entry)


def php_path(entry: str) -> str:
    return next(build.path for build in load().offered(ARCHITECTURE) if build.entry == entry)


def state(profiles: dict[str, str], digest: str = "b" * 64) -> PHPState:
    return cast(
        PHPState,
        {
            "profiles": profiles,
            "services": {},
            "modules": {"php84": ["Zend OPcache"], "php85": ["Zend OPcache"]},
            "builtins": {"php84": ["Zend OPcache"], "php85": ["Zend OPcache"]},
            "digest": digest,
        },
    )


def site(identifier: str = "alpha", runtime: str = "php84") -> ObservedSite:
    return ObservedSite(
        identifier,
        (f"{identifier}.example.com",),
        runtime,
        SiteAccount(1001, 1001, f"/var/www/{identifier}", "/usr/sbin/nologin"),
        SiteState.MANAGED,
        ObservationOutcome.OBSERVED,
        file=f"/etc/caddy/sites/{identifier}.caddy",
    )


class CatalogDetectionTests(SimpleTestCase):
    def test_a_retired_build_is_an_available_update_with_its_sites(self) -> None:
        catalog, current, old = catalog_with_old_build()
        with mock.patch("runtimes.updates.load", return_value=catalog):
            found = detect(ARCHITECTURE, {"php84": old.path}, {"php84": ("alpha",)})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].entry, "php84")
        self.assertEqual(found[0].installed.path, old.path)
        self.assertEqual(found[0].offered.path, current.path)
        self.assertEqual(found[0].sites, ("alpha",))


class CatalogUpdateReviewTests(SimpleTestCase):
    def evidence(
        self, *, other: bool = True, state_value: PHPState | None = None
    ) -> update.UpdateEvidence:
        catalog, _current, old = catalog_with_old_build()
        paths = {"php84": old.path}
        if other:
            paths["php85"] = php_path("php85")
        with mock.patch("runtimes.updates.load", return_value=catalog):
            found = detect(ARCHITECTURE, paths, {"php84": ("alpha",)})
        profiles = update.Profiles(BOOT, 1000, paths)
        return update.UpdateEvidence(
            ARCHITECTURE,
            Standing.TARGET_STACK,
            profiles,
            found,
            {"alpha": state_value if state_value is not None else state(paths)},
            ("alpha",),
            {"alpha": "/etc/caddy/sites/alpha.caddy"},
            ObservationOutcome.OBSERVED,
            (),
        )

    def test_review_names_the_exact_builds_services_and_affected_sites(self) -> None:
        evidence = self.evidence()
        catalog, _current, _old = catalog_with_old_build()
        with (
            mock.patch("runtimes.update.load", return_value=catalog),
            mock.patch("runtimes.updates.load", return_value=catalog),
        ):
            draft = update.review(evidence, PreparationInputs())
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertFalse(draft.no_changes)
            body = update.body(draft.document, BodyContext("", "", 0))
        self.assertEqual(len(body.arguments), 1)
        payload = json.loads(gzip.decompress(base64.b64decode(body.arguments[0])))
        self.assertEqual(payload["entries"][0]["entry"], "php84")
        self.assertEqual(payload["states"], {"alpha": "b" * 64})
        self.assertEqual(draft.document["states"], {"alpha": "b" * 64})

    def test_missing_other_php_runtime_refuses_the_update(self) -> None:
        evidence = self.evidence(other=False)
        catalog, _current, _old = catalog_with_old_build()
        with mock.patch("runtimes.updates.load", return_value=catalog):
            draft = update.review(evidence, PreparationInputs())
        self.assertFalse(draft.eligible)
        self.assertIn("other PHP runtime", " ".join(draft.refusals))

    def test_unavailable_site_evidence_refuses_the_update(self) -> None:
        evidence = replace(self.evidence(), states={})
        catalog, _current, _old = catalog_with_old_build()
        with mock.patch("runtimes.updates.load", return_value=catalog):
            draft = update.review(evidence, PreparationInputs())
        self.assertFalse(draft.eligible)
        self.assertIn("alpha", " ".join(draft.refusals))

    def test_current_profiles_need_no_change(self) -> None:
        _catalog, current, _old = catalog_with_old_build()
        paths = {"php84": current.path}
        evidence = update.UpdateEvidence(
            ARCHITECTURE,
            Standing.TARGET_STACK,
            update.Profiles(BOOT, 1000, paths),
            (),
            {},
            (),
            {},
            ObservationOutcome.OBSERVED,
            (),
        )
        draft = update.review(evidence, PreparationInputs())
        self.assertTrue(draft.eligible)
        self.assertTrue(draft.no_changes)
        self.assertIn("offers", str(draft.document["note"]))

    def test_body_refuses_an_invented_target_or_source(self) -> None:
        evidence = self.evidence()
        catalog, _current, _old = catalog_with_old_build()
        with mock.patch("runtimes.update.load", return_value=catalog):
            draft = update.review(evidence, PreparationInputs())
            document = draft.document
            entries = cast(list[dict[str, object]], document["entries"])
            first = entries[0]
            for mutated in (
                {
                    **document,
                    "entries": [{**first, "to": "/nix/store/" + "a" * 32 + "-other"}],
                },
                {
                    **document,
                    "entries": [
                        {
                            **first,
                            "from": "/nix/store/" + "a" * 32 + "-not-a-catalog-build",
                        }
                    ],
                },
                {**document, "states": {}},
                {**document, "architecture": "riscv64-linux"},
            ):
                with self.subTest(mutated=mutated), self.assertRaises(ValueError):
                    update.body(mutated, BodyContext("", "", 0))


class ShownRuntimeUpdateTests(SimpleTestCase):
    def test_an_older_build_shows_its_update_and_affected_sites(self) -> None:
        catalog, current, old = catalog_with_old_build()
        collected = replace(
            COLLECTED,
            architecture=Observation(ObservationOutcome.OBSERVED, ("uname -m",), "", "aarch64"),
            sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", (site(),)),
            standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
            runtimes=(
                RuntimeObservation(
                    "php84", old.path, "php84-1-link", old.version, (), "active", (), ""
                ),
                RuntimeObservation(
                    "php85",
                    php_path("php85"),
                    "php85-1-link",
                    "8.5.11",
                    (),
                    "active",
                    (),
                    "",
                ),
            ),
        )
        with (
            mock.patch("runtimes.presentation.load", return_value=catalog),
            mock.patch("runtimes.updates.load", return_value=catalog),
        ):
            rows = shown_runtimes(collected)
            updates = shown_updates(collected, rows)
        php84 = next(row for row in rows if row.entry == "php84")
        self.assertEqual(php84.update_version, current.version)
        self.assertEqual(php84.update_path, current.path)
        self.assertEqual(php84.update_sites, ("alpha",))
        self.assertEqual(php84.update_path, current.path)
        self.assertFalse(php84.can_remove)
        self.assertEqual(len(updates), 1)


class CatalogUpdatePageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Catalog", ssh_alias="catalog.example.com")
        self.catalog, self.current, self.old = catalog_with_old_build()
        self.catalog, _tool_current, self.tool_old = with_old_tool(self.catalog, "caddy")

    def record(self, runtime: RuntimeObservation, sites: tuple[ObservedSite, ...]) -> None:
        collected = replace(
            COLLECTED,
            architecture=Observation(ObservationOutcome.OBSERVED, ("uname -m",), "", "aarch64"),
            sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
            standing=HostJudgment(
                Standing.TARGET_STACK,
                (),
                (),
                (),
                (),
                (("caddy", self.tool_old.path), ("haproxy", tool_path("haproxy"))),
            ),
            runtimes=(
                runtime,
                RuntimeObservation(
                    "php85", php_path("php85"), "php85-1-link", "8.5.11", (), "active", (), ""
                ),
            ),
        )
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(attempt, collected, timezone.now())

    def test_update_available_lists_sites_and_queues_one_review(self) -> None:
        self.record(
            RuntimeObservation(
                "php84", self.old.path, "php84-1-link", "8.4.20", (), "active", (), ""
            ),
            (site(),),
        )
        with (
            mock.patch("runtimes.presentation.load", return_value=self.catalog),
            mock.patch("runtimes.updates.load", return_value=self.catalog),
            mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")),
        ):
            page = self.client.get(f"/servers/{self.server.pk}/advanced/?tab=php")
            self.assertContains(page, "Update available")
            self.assertContains(page, "sites: alpha")
            self.assertContains(page, "caddy")
            self.assertContains(page, self.tool_old.version)
            self.assertContains(page, "Review catalog update")
            response = self.client.post(
                f"/servers/{self.server.pk}/changes/prepare/", {"kind": "update_catalog"}
            )
        preparation = ChangePreparation.objects.get()
        self.assertEqual(preparation.kind_slug, "update_catalog")
        self.assertEqual(preparation.inputs, {"version": 1})
        self.assertRedirects(response, f"/changes/{preparation.pk}/")

    def test_a_site_blocks_removal_and_an_unused_runtime_offers_it(self) -> None:
        self.record(
            RuntimeObservation(
                "php84",
                self.current.path,
                "php84-1-link",
                self.current.version,
                (),
                "active",
                (),
                "",
            ),
            (site(),),
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            page = self.client.get(f"/servers/{self.server.pk}/advanced/?tab=php")
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
