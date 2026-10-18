"""The site-database change's review, native payload and Database setting.

The review is pure, so most of it is proved without a database or an SSH connection; the
page tests drive the one prepare action. A real binding is proved natively by
``disposable/test_site_database.py``.
"""

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
from runtimes.catalog import Architecture
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from . import binding, observation, site

IDENTIFIER = "alpha"
NAME = "salpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"


def facts(**values: str) -> str:
    base = {
        "principal": "0",
        "account": "0",
        "database": "0",
        "schema_any": "0",
        "privileges": "0",
        "schema": "1",
        "exposures": "0",
        "grant_option": "0",
    }
    base.update(values)
    return "".join(f"{key}\t{value}\n" for key, value in base.items())


FULL = facts(principal="1", account="1", database="1", schema_any="1", privileges="1")
PARTIAL = facts(principal="1", account="1")


def record(
    identifier: str = IDENTIFIER,
    *,
    runtime: str = "php84",
    state: str = "complete",
    uid: int = 1001,
    gid: int = 1001,
) -> dict[str, object]:
    return {
        "identifier": identifier,
        "names": [f"{identifier}.example.com"],
        "runtime": runtime,
        "state": state,
        "problem": "",
        "account": [uid, gid, f"/var/www/{identifier}", "/usr/sbin/nologin", [gid]],
    }


def evidence(
    *,
    engine: str = binding.MARIADB,
    managed: bool = True,
    site_record: dict[str, object] | None = None,
    runtime: str = "php84",
    catalog_text: str = "",
    catalog_error: str = "",
    standing: Standing = Standing.TARGET_STACK,
    architecture: Architecture | None = Architecture.X86_64,
) -> site.SiteBindingEvidence:
    return site.SiteBindingEvidence(
        architecture=architecture,
        standing=standing,
        engine=engine,
        engine_managed=managed,
        outside=(),
        site=site_record if site_record is not None else record(runtime=runtime),
        runtime=runtime,
        site_digest="a" * 64,
        boot_id=BOOT,
        uptime_centiseconds=100,
        catalog_text=catalog_text,
        catalog_error=catalog_error,
    )


def review(value: site.SiteBindingEvidence) -> ReviewDraft:
    return site.review(value, PreparationInputs("", IDENTIFIER))


class BindingRecognitionTests(ControllerConfigTestCase):
    def test_an_absent_binding_is_empty(self) -> None:
        result = binding.recognize(
            binding.MARIADB, IDENTIFIER, binding.parse_facts(binding.MARIADB, facts())
        )
        self.assertEqual(result.state, "absent")
        self.assertEqual(result.completed, ())

    def test_a_full_binding_is_satisfied_over_its_steps(self) -> None:
        result = binding.recognize(
            binding.MARIADB, IDENTIFIER, binding.parse_facts(binding.MARIADB, FULL)
        )
        self.assertEqual(result.state, "satisfied")
        self.assertEqual(result.completed, binding.MARIADB_STEPS)

    def test_a_principal_only_binding_is_partial(self) -> None:
        result = binding.recognize(
            binding.MARIADB, IDENTIFIER, binding.parse_facts(binding.MARIADB, PARTIAL)
        )
        self.assertEqual(result.state, "partial")
        self.assertEqual(result.completed, ("principal",))

    def test_a_foreign_grant_is_custom(self) -> None:
        result = binding.recognize(
            binding.MARIADB,
            IDENTIFIER,
            binding.parse_facts(binding.MARIADB, facts(principal="1", account="1", exposures="1")),
        )
        self.assertEqual(result.state, "custom")

    def test_a_grant_option_is_custom(self) -> None:
        result = binding.recognize(
            binding.POSTGRESQL,
            IDENTIFIER,
            binding.parse_facts(binding.POSTGRESQL, facts(principal="1", grant_option="1")),
        )
        self.assertEqual(result.state, "custom")


class SiteBindingReviewTests(ControllerConfigTestCase):
    def test_an_absent_binding_reviews_every_statement(self) -> None:
        draft = review(evidence(catalog_text=facts()))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(len(draft.effects), 1)
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        self.assertEqual(draft.effects[0].sites, (IDENTIFIER,))
        rows = cast(list[list[str]], draft.document["statements"])
        self.assertEqual([row[0] for row in rows], list(binding.MARIADB_STEPS))
        self.assertEqual(draft.current_sites, (IDENTIFIER,))

    def test_a_partial_binding_reviews_only_the_rest(self) -> None:
        draft = review(evidence(catalog_text=PARTIAL))
        self.assertTrue(draft.eligible, draft.refusals)
        rows = cast(list[list[str]], draft.document["statements"])
        self.assertEqual([row[0] for row in rows], ["database", "privileges"])

    def test_a_satisfied_binding_proposes_no_changes(self) -> None:
        draft = review(evidence(catalog_text=FULL))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertIn("already exists", str(draft.document["note"]))

    def test_a_custom_binding_is_refused(self) -> None:
        draft = review(evidence(catalog_text=facts(principal="1", account="1", exposures="1")))
        self.assertFalse(draft.eligible)
        self.assertTrue(
            any("does not follow the convention" in reason for reason in draft.refusals)
        )

    def test_a_missing_engine_is_refused(self) -> None:
        draft = review(evidence(engine="", catalog_text=""))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("no database engine" in reason for reason in draft.refusals))

    def test_a_missing_foundation_is_refused(self) -> None:
        draft = review(evidence(catalog_text=facts(), standing=Standing.FRESH))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("foundation" in reason for reason in draft.refusals))

    def test_an_incomplete_site_is_refused(self) -> None:
        draft = review(evidence(catalog_text=facts(), site_record=record(state="partial")))
        self.assertFalse(draft.eligible)
        self.assertTrue(any("not complete" in reason for reason in draft.refusals))

    def test_postgresql_needs_a_supported_locale(self) -> None:
        draft = review(
            evidence(
                engine=binding.POSTGRESQL,
                catalog_text=facts(schema="0") + "template|UTF8|i|C|C\n",
            )
        )
        self.assertFalse(draft.eligible)
        self.assertTrue(any("locale" in reason for reason in draft.refusals))

    def test_the_body_rebuilds_from_the_review(self) -> None:
        draft = review(evidence(catalog_text=facts()))
        body = site.body(draft.document, BodyContext("unit", BOOT, 1))
        self.assertEqual(body.source, site.BODY_BYTES)
        self.assertEqual(len(body.arguments), 1)

    def test_a_tampered_statement_is_not_a_body(self) -> None:
        draft = review(evidence(catalog_text=facts()))
        document = dict(draft.document)
        statements = [list(row) for row in cast(list[list[str]], document["statements"])]
        statements[0][2] = "DROP DATABASE mysql"
        document["statements"] = statements
        with self.assertRaises(ValueError):
            site.body(document, BodyContext("unit", BOOT, 1))


class SiteBindingPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_changes", "change_site", "view_siteobservation")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="DB", ssh_alias="db.example.com")

    def snapshot(self, *components: WebStackComponentObservation) -> None:
        collected = _collected(*components, site_identifier=IDENTIFIER)
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(attempt, collected, timezone.now())

    def test_the_database_page_shows_connection_details_and_queues_a_review(self) -> None:
        self.snapshot(_component(binding.MARIADB, "1:11.8.6-5ubuntu0.1"))
        response = self.client.get(f"/servers/{self.server.pk}/sites/{IDENTIFIER}/database/")
        self.assertContains(response, "Database")
        self.assertContains(response, "MariaDB")
        self.assertContains(response, NAME)
        self.assertContains(response, "Add database")
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            queued = self.client.post(
                f"/servers/{self.server.pk}/sites/{IDENTIFIER}/database/prepare/",
                {},
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(queued, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "identifier": IDENTIFIER})

    def test_the_page_asks_for_an_engine_first(self) -> None:
        self.snapshot()
        response = self.client.get(f"/servers/{self.server.pk}/sites/{IDENTIFIER}/database/")
        self.assertContains(response, "Install one database engine")

    def test_a_viewer_cannot_queue_a_site_database(self) -> None:
        self.snapshot(_component(binding.MARIADB, "1:11.8.6-5ubuntu0.1"))
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/{IDENTIFIER}/database/prepare/",
            {},
        )
        self.assertEqual(response.status_code, 403)


class SiteBindingInputTests(ControllerConfigTestCase):
    def test_the_shape_accepts_one_identifier(self) -> None:
        value = decode_inputs(
            {"version": 1, "identifier": IDENTIFIER}, (), InputShape.SITE_DATABASE
        )
        self.assertEqual(value, PreparationInputs("", IDENTIFIER))

    def test_the_shape_rejects_an_unknown_identifier(self) -> None:
        with self.assertRaises(ValueError):
            decode_inputs({"version": 1, "identifier": "A"}, (), InputShape.SITE_DATABASE)


def _collected(
    *components: WebStackComponentObservation, site_identifier: str
) -> CollectedSnapshot:
    from discovery.models import SiteState
    from discovery.snapshot import ObservedSite, SiteAccount

    site_value = ObservedSite(
        site_identifier,
        (f"{site_identifier}.example.com",),
        "php84",
        SiteAccount(1001, 1001, f"/var/www/{site_identifier}", "/usr/sbin/nologin"),
        SiteState.MANAGED,
        ObservationOutcome.OBSERVED,
        file=f"/etc/caddy/sites/{site_identifier}.caddy",
    )
    return CollectedSnapshot(
        os=COLLECTED.os,
        architecture=COLLECTED.architecture,
        cpu_count=COLLECTED.cpu_count,
        memory_bytes=COLLECTED.memory_bytes,
        filesystem=COLLECTED.filesystem,
        components=components,
        sites=Observation(ObservationOutcome.OBSERVED, ("/etc/caddy/sites",), "", (site_value,)),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
    )


def _component(engine: str, version: str) -> WebStackComponentObservation:
    spec = observation.specs()[engine]
    return WebStackComponentObservation(
        spec.component,
        Observation(
            ObservationOutcome.OBSERVED, ("dpkg-query",), "", (Package(spec.versioned, version),)
        ),
        Observation(
            ObservationOutcome.OBSERVED,
            ("systemctl",),
            "",
            (ServiceUnit(spec.units[0], "loaded", "active", "running", "enabled"),),
        ),
    )
