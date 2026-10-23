from dataclasses import replace
from typing import cast
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import Standing
from discovery.models import ObservationOutcome
from operations.consent import consent_of
from operations.engine import BodyContext
from operations.inputs import PreparationInputs
from operations.models import Consent
from sites.bodies.php_runtime import PHPState

from . import update
from .catalog import Architecture, Build, Catalog, load
from .revert import RevertEvidence, review

ARCHITECTURE = Architecture.AARCH64
BOOT = "12345678-1234-1234-1234-123456789abc"


def catalog_with_old_build() -> tuple[Catalog, Build, Build]:
    real = load()
    current = next(build for build in real.offered(ARCHITECTURE) if build.entry == "php84")
    old = replace(
        current,
        path="/nix/store/" + "a" * 32 + "-php84-previous",
        version="8.4.20",
        retired=True,
    )
    return replace(real, builds=(*real.builds, old)), current, old


def php_path(entry: str) -> str:
    return next(build.path for build in load().offered(ARCHITECTURE) if build.entry == entry)


def state(paths: dict[str, str]) -> PHPState:
    return cast(
        PHPState,
        {
            "profiles": paths,
            "services": {},
            "modules": {"php84": ["Zend OPcache"], "php85": ["Zend OPcache"]},
            "builtins": {"php84": ["Zend OPcache"], "php85": ["Zend OPcache"]},
            "digest": "b" * 64,
        },
    )


def evidence(*, previous: bool = True, other: bool = True) -> RevertEvidence:
    _catalog, current, old = catalog_with_old_build()
    paths = {"php84": current.path}
    if other:
        paths["php85"] = php_path("php85")
    return RevertEvidence(
        ARCHITECTURE,
        Standing.TARGET_STACK,
        update.Profiles(BOOT, 1000, paths, {"php84": old.path} if previous else {}),
        {"alpha": state(paths)},
        ("alpha",),
        ("alpha",),
        {"alpha": "/etc/caddy/sites/alpha.caddy"},
        ObservationOutcome.OBSERVED,
        (),
    )


class RuntimeRevertReviewTests(SimpleTestCase):
    def test_revert_names_the_current_and_previous_builds_and_keeps_sites_serving(self) -> None:
        catalog, current, old = catalog_with_old_build()
        with mock.patch("runtimes.revert.load", return_value=catalog):
            draft = review(evidence(), PreparationInputs("php84"))
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertEqual(consent_of(draft.effects), Consent.SHARED)
            entries = cast(list[dict[str, object]], draft.document["entries"])
            self.assertEqual(entries[0]["from"], current.path)
            self.assertEqual(entries[0]["to"], old.path)
            self.assertEqual(entries[0]["sites"], ["alpha"])
            with mock.patch("runtimes.update.load", return_value=catalog):
                body = update.body(draft.document, BodyContext("", "", 0))
        self.assertEqual(len(body.arguments), 1)

    def test_a_runtime_without_a_known_previous_build_is_refused(self) -> None:
        catalog, _current, _old = catalog_with_old_build()
        with mock.patch("runtimes.revert.load", return_value=catalog):
            draft = review(evidence(previous=False), PreparationInputs("php84"))
        self.assertFalse(draft.eligible)
        self.assertIn("nothing to revert", " ".join(draft.refusals))

    def test_a_site_without_the_other_runtime_is_refused(self) -> None:
        catalog, _current, _old = catalog_with_old_build()
        with mock.patch("runtimes.revert.load", return_value=catalog):
            draft = review(evidence(other=False), PreparationInputs("php84"))
        self.assertFalse(draft.eligible)
        self.assertIn("other PHP runtime", " ".join(draft.refusals))

    def test_body_refuses_an_unknown_previous_build(self) -> None:
        catalog, _current, _old = catalog_with_old_build()
        with mock.patch("runtimes.revert.load", return_value=catalog):
            draft = review(evidence(), PreparationInputs("php84"))
            entries = cast(list[dict[str, object]], draft.document["entries"])
            for mutated in (
                {
                    **draft.document,
                    "entries": [
                        {**entries[0], "to": "/nix/store/" + "a" * 32 + "-not-a-catalog-build"}
                    ],
                },
                {**draft.document, "states": {}},
            ):
                with (
                    self.subTest(mutated=mutated),
                    mock.patch("runtimes.update.load", return_value=catalog),
                    self.assertRaises(ValueError),
                ):
                    update.body(mutated, BodyContext("", "", 0))
