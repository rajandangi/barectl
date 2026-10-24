"""The certificate contact email setting, its review and its Server Settings journey (#444)."""

from dataclasses import replace
from typing import cast, override
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.observations import caddy_email
from discovery.snapshot import (
    CollectedSnapshot,
    Observation,
    save_snapshot,
)
from discovery.ssh import CommandResult, RemoteShell
from operations.consent import Scope
from operations.engine import BodyContext
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.services import read_changes
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from . import certificate_email
from .certificate_email import (
    ABSENT,
    OUTSIDE,
    SET,
    UNREADABLE,
    CertificateEmailEvidence,
)

BASE = """{
\tadmin unix//run/caddy/admin.sock|0600
\tservers {
\t\tstrict_sni_host on
\t}
}
import sites/*.caddy
:80 {
\trespond 404
}
"""
WITH_EMAIL = BASE.replace("\tservers {", "\temail ops@example.com\n\tservers {", 1)
UNSAFE = "0 0 666 1 regular file"


def evidence(
    *,
    previous: str = BASE,
    standing: Standing | None = Standing.TARGET_STACK,
    sites: tuple[str, ...] | None = ("alpha", "beta"),
    metadata: str = "0 0 644 1 regular file",
    state: str | None = None,
) -> CertificateEmailEvidence:
    observed_state, current = certificate_email.email_state(previous)
    return CertificateEmailEvidence(
        standing=standing,
        boot_id="12345678-1234-1234-1234-123456789abc",
        uptime_centiseconds=1000,
        file_metadata=metadata,
        file_state=state or observed_state,
        previous=previous,
        current=current,
        sites=sites,
    )


def inputs(email: str) -> PreparationInputs:
    return PreparationInputs(certificate_email=email)


class RenderTests(SimpleTestCase):
    def test_the_email_is_added_after_the_admin_line_and_every_other_line_stays(self) -> None:
        rendered = certificate_email.render_main(BASE, "ops@example.com")
        self.assertEqual(certificate_email.email_state(rendered), (SET, "ops@example.com"))
        self.assertIn(
            "\tadmin unix//run/caddy/admin.sock|0600\n\temail ops@example.com\n", rendered
        )
        self.assertIn("import sites/*.caddy", rendered)
        self.assertIn(":80 {\n\trespond 404\n}", rendered)

    def test_an_existing_email_is_replaced_or_removed_without_touching_other_options(self) -> None:
        fixture = BASE.replace(
            "\tadmin unix//run/caddy/admin.sock|0600\n",
            "\tadmin unix//run/caddy/admin.sock|0600\n"
            "\tacme_ca https://pebble:14000/dir\n"
            "\temail fixture@barectl.test\n",
            1,
        )
        replaced = certificate_email.render_main(fixture, "ops@fixture.test")
        self.assertIn("\tacme_ca https://pebble:14000/dir\n", replaced)
        self.assertIn("\temail ops@fixture.test\n", replaced)
        self.assertNotIn("fixture@barectl.test", replaced)
        removed = certificate_email.render_main(replaced, "")
        self.assertNotIn("email ", removed)
        self.assertIn("\tacme_ca https://pebble:14000/dir\n", removed)

    def test_a_file_outside_the_supported_global_block_is_refused(self) -> None:
        for previous in ("# comment\n" + BASE, BASE.replace("}\nimport", "\nimport", 1), ""):
            with self.subTest(previous=previous[:20]), self.assertRaises(ValueError):
                certificate_email.render_main(previous, "ops@example.com")
        duplicate = BASE.replace(
            "\tservers {", "\temail one@example.com\n\temail two@example.com\n\tservers {", 1
        )
        self.assertEqual(certificate_email.email_state(duplicate), (OUTSIDE, ""))
        with self.assertRaises(ValueError):
            certificate_email.render_main(duplicate, "ops@example.com")

    def test_the_discovery_state_reads_the_rendered_file(self) -> None:
        cases = (
            (BASE, ABSENT, ""),
            (WITH_EMAIL, SET, "ops@example.com"),
            (BASE.replace("{", "{\n\temail", 1), OUTSIDE, ""),
            (BASE.replace("{", "{\n\temail one@x.test\n\temail two@x.test", 1), OUTSIDE, ""),
            ("sites/*.caddy\n", OUTSIDE, ""),
        )
        for text, state, value in cases:
            with self.subTest(state=state):
                self.assertEqual(certificate_email.email_state(text), (state, value))

    def test_the_setting_accepts_one_bare_address_or_removal(self) -> None:
        for value in ("", "ops@example.com", "ops.team@mail.example.co.uk"):
            with self.subTest(value=value):
                self.assertTrue(certificate_email.valid_email(value))
        for value in (
            "ops",
            "ops@example",
            "a b@example.com",
            "ops@exam ple.com",
            "ops#x@example.com",
            "ops{x}@example.com",
            'ops"x@example.com',
            "x" * 255,
        ):
            with self.subTest(value=value):
                self.assertFalse(certificate_email.valid_email(value))


class InputTests(SimpleTestCase):
    def test_the_reviewed_inputs_round_trip_with_or_without_an_address(self) -> None:
        for value in ("", "ops@example.com"):
            with self.subTest(value=value):
                decoded = decode_inputs(
                    {"version": 1, "email": value}, (), InputShape.CERTIFICATE_EMAIL
                )
                self.assertEqual(decoded.certificate_email, value)
                self.assertEqual(decoded.document(), {"version": 1, "email": value})

    def test_forged_inputs_are_refused(self) -> None:
        for value in (
            {"version": 1},
            {"version": 1, "email": None},
            {"version": 1, "email": "not an address"},
            {"version": 2, "email": "ops@example.com"},
            {"version": 1, "email": "ops@example.com", "selection": "php84"},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_inputs(value, (), InputShape.CERTIFICATE_EMAIL)


class ReviewTests(SimpleTestCase):
    def test_setting_the_email_is_one_shared_effect_over_every_site(self) -> None:
        draft = certificate_email.review(evidence(), inputs("ops@example.com"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SHARED])
        self.assertEqual(draft.effects[0].sites, ("alpha", "beta"))
        self.assertEqual(draft.current_sites, ("alpha", "beta"))
        self.assertIn("email ops@example.com", str(draft.document["caddy"]))
        self.assertEqual(draft.stages, ("preflight", "caddy", "verify"))

    def test_removing_the_email_publishes_a_file_without_the_line(self) -> None:
        draft = certificate_email.review(evidence(previous=WITH_EMAIL), inputs(""))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertNotIn("email ", str(draft.document["caddy"]))
        self.assertEqual(draft.document["email"], "")

    def test_the_same_address_proposes_no_changes(self) -> None:
        draft = certificate_email.review(evidence(previous=WITH_EMAIL), inputs("ops@example.com"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertIn("already", str(draft.document["note"]))

    def test_a_host_without_the_foundation_is_refused(self) -> None:
        draft = certificate_email.review(
            evidence(standing=Standing.FRESH), inputs("ops@example.com")
        )
        self.assertFalse(draft.eligible)
        self.assertIn("foundation", " ".join(draft.refusals))

    def test_unsafe_or_outside_evidence_is_refused(self) -> None:
        cases = (
            evidence(metadata=UNSAFE),
            evidence(state=UNREADABLE),
            evidence(state=OUTSIDE),
            evidence(sites=None),
        )
        for item in cases:
            with self.subTest(item=item):
                draft = certificate_email.review(item, inputs("ops@example.com"))
                self.assertFalse(draft.eligible)
                self.assertTrue(draft.refusals)

    def test_a_forged_native_selection_is_refused_before_apply(self) -> None:
        draft = certificate_email.review(evidence(), inputs("ops@example.com"))
        context = BodyContext("", "", 0)
        native = certificate_email.body(draft.document, context)
        self.assertEqual(len(native.arguments), 1)
        for document in (
            {**draft.document, "caddy": BASE},
            {**draft.document, "email": "other@example.com"},
            {**draft.document, "version": True},
            {**draft.document, "previous": "not the preimage"},
        ):
            with self.subTest(document=document.get("email")), self.assertRaises(ValueError):
                certificate_email.body(document, context)


def target_snapshot(
    server: Server,
    *,
    email: str = "",
    state: str = ABSENT,
    standing: Standing = Standing.TARGET_STACK,
) -> None:
    collected: CollectedSnapshot = replace(
        COLLECTED,
        components=(),
        sites=Observation(ObservationOutcome.OBSERVED, ("/etc/caddy/sites",), "", ()),
        standing=HostJudgment(standing, (), (), ()),
        certificate_email=email,
        certificate_email_state=state,
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())


class CertificateEmailPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="HTTPS", ssh_alias="https.example.com")

    def test_the_panel_shows_the_observed_address_and_queues_a_review(self) -> None:
        target_snapshot(self.server, email="ops@example.com", state=SET)
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(response, "HTTPS")
        self.assertContains(response, "Certificate contact email")
        self.assertContains(response, "mailto:ops@example.com")
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            queued = self.client.post(
                f"/servers/{self.server.pk}/settings/certificate-email/prepare/",
                {"email": "ops@example.com"},
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(queued, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "email": "ops@example.com"})
        self.server.refresh_from_db()
        self.assertEqual(self.server.certificate_email, "ops@example.com")

    def test_the_panel_shows_not_set_and_offers_removal(self) -> None:
        target_snapshot(self.server)
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(
            response, "Not set. Caddy requests certificates without a contact address."
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            queued = self.client.post(
                f"/servers/{self.server.pk}/settings/certificate-email/prepare/",
                {"email": ""},
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(queued, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "email": ""})

    def test_an_outside_main_configuration_offers_no_control(self) -> None:
        target_snapshot(self.server, state=OUTSIDE)
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(response, "outside supported settings")
        self.assertNotContains(response, "Prepare review")
        response = self.client.post(
            f"/servers/{self.server.pk}/settings/certificate-email/prepare/",
            {"email": "ops@example.com"},
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/settings/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_no_observation_shows_the_saved_value_without_a_control(self) -> None:
        self.server.certificate_email = "saved@example.com"
        self.server.save(update_fields=["certificate_email"])
        response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertContains(response, "has not been observed yet")
        self.assertContains(response, "saved@example.com")
        self.assertNotContains(response, "Prepare review")

    def test_an_invalid_address_is_refused(self) -> None:
        target_snapshot(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/settings/certificate-email/prepare/",
            {"email": "not an address"},
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/settings/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_viewer_cannot_queue_the_setting(self) -> None:
        target_snapshot(self.server)
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/settings/certificate-email/prepare/",
            {"email": "ops@example.com"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])


class DiscoveryTests(SimpleTestCase):
    class Shell:
        def __init__(self, result: CommandResult) -> None:
            self.result = result

        def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
            return self.result

    def test_the_reader_reports_the_rendered_setting(self) -> None:
        self.assertEqual(
            caddy_email.read(cast(RemoteShell, self.Shell(CommandResult(0, WITH_EMAIL)))),
            (SET, "ops@example.com"),
        )
        self.assertEqual(
            caddy_email.read(cast(RemoteShell, self.Shell(CommandResult(1, "")))),
            (UNREADABLE, ""),
        )
