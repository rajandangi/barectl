"""Domains and HTTPS: the reviewed change, its refusals and the Settings journey (#442)."""

from typing import cast, override
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import Standing
from operations.consent import Scope
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.bodies.common import NativeState
from sites.domains_change import SLUG, DomainsEvidence, body, review
from sites.forms import SiteDomainsForm
from sites.ui_testing import record_http_sites


def evidence(
    *,
    names: tuple[str, ...] = ("alpha.example.com",),
    https: bool = True,
    form: str = "plain",
    state: str = "complete",
    dns: dict[str, object] | None = None,
) -> DomainsEvidence:
    native: dict[str, object] = {
        "version": 1,
        "digest": "a" * 64,
        "disk_digest": "b" * 64,
        "boot": "00000000-0000-0000-0000-000000000000",
        "uptime": 1,
        "current_sites": [],
        "evidence": {},
        "next_id": 4002,
        "next_proxy_id": 4003,
        "validation": "not_requested",
        "pool_validation": "not_requested",
        "master_present": True,
        "sites": [
            {
                "identifier": "alpha",
                "names": list(names),
                "runtime": "php84",
                "node_runtime": "",
                "https": https,
                "readiness": "/",
                "certificate": None,
                "account": [4000, 4000, "/var/www/alpha", "/usr/sbin/nologin", [4000]],
                "file": "/etc/caddy/sites/alpha.caddy",
                "state": state,
                "problem": "",
                "serving_form": form,
                "pool": None,
                "application": "plain",
                "application_version": "",
                "application_problem": "",
            },
            {
                "identifier": "beta",
                "names": ["beta.example.com"],
                "runtime": "php84",
                "node_runtime": "",
                "https": True,
                "readiness": "/",
                "certificate": None,
                "account": [4001, 4001, "/var/www/beta", "/usr/sbin/nologin", [4001]],
                "file": "/etc/caddy/sites/beta.caddy",
                "state": "complete",
                "problem": "",
                "serving_form": "plain",
                "pool": None,
                "application": "plain",
                "application_version": "",
                "application_problem": "",
            },
        ],
    }
    return DomainsEvidence(Standing.TARGET_STACK, cast(NativeState, native), dns)


def inputs(
    names: tuple[str, ...] = ("alpha.example.com", "www.example.com"),
    https: bool = True,
) -> PreparationInputs:
    return PreparationInputs(identifier="alpha", names=names, https=https, domains=True)


class DomainsFormTests(SimpleTestCase):
    def test_the_form_accepts_names_and_https_and_refuses_invalid_names(self) -> None:
        valid = SiteDomainsForm({"names": "alpha.example.com www.example.com", "https": "on"})
        self.assertTrue(valid.is_valid(), valid.errors)
        self.assertEqual(valid.cleaned_data["names"], ("alpha.example.com", "www.example.com"))
        self.assertTrue(valid.cleaned_data["https"])
        for names in ("", "not a domain"):
            with self.subTest(names=names):
                self.assertFalse(SiteDomainsForm({"names": names}).is_valid())


class DomainsInputTests(SimpleTestCase):
    def test_the_reviewed_inputs_round_trip(self) -> None:
        value = {
            "version": 1,
            "identifier": "alpha",
            "names": ["alpha.example.com", "www.example.com"],
            "https": True,
        }
        decoded = decode_inputs(value, (), InputShape.SITE_DOMAINS)
        self.assertEqual(decoded.identifier, "alpha")
        self.assertEqual(decoded.names, ("alpha.example.com", "www.example.com"))
        self.assertEqual(decoded.document(), value)

    def test_forged_or_non_canonical_inputs_are_refused(self) -> None:
        base = {
            "version": 1,
            "identifier": "alpha",
            "names": ["alpha.example.com"],
            "https": True,
        }
        for value in (
            base | {"selection": "php84"},
            base | {"https": "on"},
            base | {"names": []},
            base | {"identifier": "Alpha"},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_inputs(value, (), InputShape.SITE_DOMAINS)


class DomainsReviewTests(SimpleTestCase):
    def test_a_changed_site_is_one_shared_effect_and_names_the_other_sites(self) -> None:
        draft = review(evidence(), inputs())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SHARED])
        self.assertEqual(draft.effects[0].sites, ("alpha", "beta"))
        self.assertEqual(draft.current_sites, ("alpha", "beta"))
        self.assertEqual(draft.document["form"], "plain")
        self.assertIn("www.example.com", str(draft.document["details"]))

    def test_an_unchanged_site_proposes_no_changes(self) -> None:
        draft = review(evidence(), inputs(("alpha.example.com",)))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)

    def test_an_http_only_site_can_turn_https_on(self) -> None:
        draft = review(evidence(https=False), inputs(https=True))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertIn("alpha.example.com, www.example.com {", str(draft.document["caddy"]))
        self.assertNotIn("http://alpha.example.com", str(draft.document["caddy"]))

    def test_wordpress_and_laravel_aliases_are_redirected(self) -> None:
        for form in ("wordpress", "laravel"):
            with self.subTest(form=form):
                draft = review(evidence(form=form), inputs())
                self.assertTrue(draft.eligible, draft.refusals)
                caddy = str(draft.document["caddy"])
                self.assertIn("@alias expression", caddy)
                self.assertIn("redir @alias https://alpha.example.com{uri} permanent", caddy)

    def test_a_plain_site_serves_aliases_without_a_redirect(self) -> None:
        draft = review(evidence(), inputs())
        self.assertNotIn("redir @alias", str(draft.document["caddy"]))

    def test_a_partial_site_is_refused(self) -> None:
        draft = review(evidence(state="partial"), inputs())
        self.assertFalse(draft.eligible)
        self.assertTrue(draft.refusals)

    def test_a_dns_mismatch_warns_without_refusing(self) -> None:
        draft = review(
            evidence(dns={"local": ["10.0.0.1"], "resolved": {}}),
            inputs(),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertIn("does not resolve", str(draft.document["details"]))
        self.assertIn("does not resolve", str(draft.document["acknowledgement"]))

    def test_a_forged_document_is_refused_before_apply(self) -> None:
        draft = review(evidence(), inputs())
        document = dict(draft.document)
        document["names"] = ["evil.example.com"]
        with self.assertRaises(ValueError):
            body(document, mock.Mock())

    def test_the_body_accepts_its_own_review(self) -> None:
        draft = review(evidence(), inputs())
        self.assertIsNotNone(body(dict(draft.document), mock.Mock()))


class DomainsPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_http_sites(self.server)

    def test_settings_shows_the_domains_section_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/settings/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Domains and HTTPS")
        self.assertContains(response, "alpha.example.com")
        self.assertContains(response, "Change domains and HTTPS")

    def test_the_prepare_request_queues_the_change_without_ssh(self) -> None:
        from operations.services import read_changes

        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(
                f"/servers/{self.server.pk}/sites/alpha/settings/domains/prepare/",
                {"names": "alpha.example.com www.example.com", "https": "on"},
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].preparation.kind_slug, SLUG)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "names": ["alpha.example.com", "www.example.com"],
                "https": True,
            },
        )
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_a_viewer_cannot_prepare_a_domains_change(self) -> None:
        from operations.services import read_changes

        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/settings/domains/prepare/",
            {"names": "alpha.example.com"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])
