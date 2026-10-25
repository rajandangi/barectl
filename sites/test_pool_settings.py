"""Site PHP settings: form bounds, review consent, native rendering and reconstruction."""

from typing import cast, override
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import Standing
from discovery.snapshot import current_snapshot
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.services import read_changes
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.bodies.common import NativeState
from sites.bodies.pool import (
    SitePool,
    parse_pool,
    render_pool_settings,
    supported_pool,
)
from sites.configuration import SiteSettings, render_pool
from sites.pool_change import PoolEvidence, review
from sites.pool_forms import SitePoolForm
from sites.ui_testing import record_http_sites


def pool(**values: object) -> SitePool:
    document = SitePool().document()
    document.update(values)
    result = SitePool.from_document(document)
    if result is None:
        raise AssertionError("The test pool is invalid.")
    return result


def invalid(document: dict[str, object], **values: object) -> dict[str, object]:
    document.update(values)
    return document


class SitePoolFormTests(SimpleTestCase):
    def test_each_setting_refuses_values_outside_its_bound(self) -> None:
        accepted = {
            "process_manager": "static",
            "max_children": "8",
            "slowlog_timeout": "10",
            "terminate_timeout": "120",
            "memory_limit": "256",
            "upload_max_filesize": "64",
            "post_max_size": "64",
        }
        valid = SitePoolForm(accepted)
        self.assertTrue(valid.is_valid(), valid.errors)
        for field, value in (
            ("max_children", "0"),
            ("max_children", "65"),
            ("slowlog_timeout", "0"),
            ("slowlog_timeout", "301"),
            ("memory_limit", "15"),
            ("memory_limit", "1025"),
            ("upload_max_filesize", "0"),
            ("upload_max_filesize", "257"),
            ("post_max_size", "257"),
        ):
            with self.subTest(field=field, value=value):
                self.assertFalse(SitePoolForm(accepted | {field: value}).is_valid())

    def test_dynamic_spares_must_be_bounded_and_ordered(self) -> None:
        base = {
            "process_manager": "dynamic",
            "max_children": "6",
            "start_servers": "3",
            "min_spare_servers": "2",
            "max_spare_servers": "4",
        }
        valid = SitePoolForm(base)
        self.assertTrue(valid.is_valid(), valid.errors)
        for values in (
            base | {"start_servers": ""},
            base | {"max_spare_servers": "7"},
            base | {"start_servers": "1", "min_spare_servers": "2"},
        ):
            with self.subTest(values=values):
                self.assertFalse(SitePoolForm(values).is_valid())

    def test_manager_specific_fields_are_refused_elsewhere(self) -> None:
        for values in (
            {"process_manager": "static", "max_children": "4", "start_servers": "2"},
            {"process_manager": "static", "max_children": "4", "process_idle_timeout": "10"},
            {"process_manager": "ondemand", "max_children": "4", "start_servers": "2"},
        ):
            with self.subTest(values=values):
                self.assertFalse(SitePoolForm(values).is_valid())


class PoolRenderingTests(SimpleTestCase):
    def test_a_supported_pool_round_trips_and_rewrites_only_its_tunables(self) -> None:
        settings = SiteSettings("shop", ("shop.example.com",), "php84")
        original = render_pool(settings) + "# operator note\n"
        self.assertTrue(supported_pool("shop", "php84", original))
        selected = pool(
            process_manager="ondemand",
            max_children=12,
            process_idle_timeout=15,
            slowlog_timeout=8,
            terminate_timeout=120,
            memory_limit=256,
            upload_max_filesize=64,
            post_max_size=64,
        )
        changed = render_pool_settings(original, selected)
        self.assertIn("pm = ondemand\n", changed)
        self.assertIn("pm.max_children = 12\n", changed)
        self.assertIn("pm.process_idle_timeout = 15s\n", changed)
        self.assertIn("php_admin_value[memory_limit] = 256M\n", changed)
        self.assertIn("php_admin_value[upload_tmp_dir] = /var/www/shop/private/tmp\n", changed)
        self.assertIn("# operator note\n", changed)
        self.assertEqual(parse_pool("shop", "php84", changed), selected)

    def test_leaving_an_optional_limit_blank_removes_it(self) -> None:
        settings = SiteSettings("shop", ("shop.example.com",), "php84")
        changed = render_pool_settings(render_pool(settings), SitePool())
        self.assertNotIn("php_admin_value[memory_limit]", changed)
        self.assertEqual(parse_pool("shop", "php84", changed), SitePool())


def evidence(selected: SitePool | None, *, state: str = "complete") -> PoolEvidence:
    native: dict[str, object] = {
        "digest": "a" * 64,
        "boot": "00000000-0000-0000-0000-000000000000",
        "uptime": 1,
        "sites": [
            {
                "identifier": "shop",
                "names": ["shop.example.com"],
                "runtime": "php84",
                "node_runtime": "",
                "https": True,
                "readiness": "/",
                "certificate": None,
                "pool": selected.document() if selected is not None else None,
                "account": [4000, 4000, "/var/www/shop", "/usr/sbin/nologin", [4000]],
                "file": "/etc/caddy/sites/shop.caddy",
                "state": state,
                "problem": "",
            }
        ],
    }
    return PoolEvidence(Standing.TARGET_STACK, cast(NativeState, native))


class PoolReviewTests(SimpleTestCase):
    def test_a_changed_pool_is_one_site_effect(self) -> None:
        from operations.consent import Scope

        draft = review(
            evidence(SitePool()),
            PreparationInputs("", "shop", pool=pool(max_children=8)),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE])
        self.assertEqual(draft.current_sites, ("shop",))

    def test_the_same_pool_proposes_no_changes(self) -> None:
        draft = review(evidence(SitePool()), PreparationInputs("", "shop", pool=SitePool()))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)

    def test_an_unreadable_or_incomplete_pool_is_refused(self) -> None:
        for observed, state in ((None, "complete"), (SitePool(), "unsupported")):
            with self.subTest(state=state):
                draft = review(
                    evidence(observed, state=state),
                    PreparationInputs("", "shop", pool=pool(max_children=8)),
                )
                self.assertFalse(draft.eligible)

    def test_a_review_refuses_values_outside_the_bounds(self) -> None:
        for selected in (
            SitePool(max_children=65),
            SitePool(process_manager="static", start_servers=2),
            SitePool(process_manager="static", process_idle_timeout=10),
        ):
            with self.subTest(pool=selected):
                draft = review(evidence(SitePool()), PreparationInputs("", "shop", pool=selected))
                self.assertFalse(draft.eligible)
                self.assertIn("supported bounds", " ".join(draft.refusals))

    def test_invalid_review_inputs_are_refused(self) -> None:
        for document in (
            invalid(SitePool().document(), max_children=65),
            invalid(SitePool().document(), memory_limit=8),
            invalid(SitePool().document(), start_servers=2),
            invalid(SitePool().document(), process_idle_timeout=10),
            {"max_children": 2},
        ):
            with self.subTest(document=document), self.assertRaises(ValueError):
                decode_inputs(
                    {"version": 1, "identifier": "shop", "pool": document},
                    (),
                    InputShape.SITE_POOL,
                )


class SitePoolPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="PHP", ssh_alias="php.example.com")
        record_http_sites(self.server)
        self.url = f"/servers/{self.server.pk}/sites/alpha/runtime/php-settings/prepare/"

    def test_post_queues_only_a_versioned_pool_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(
                self.url,
                {
                    "process_manager": "static",
                    "max_children": "8",
                    "slowlog_timeout": "10",
                    "terminate_timeout": "120",
                    "memory_limit": "256",
                    "upload_max_filesize": "64",
                    "post_max_size": "64",
                    "identifier": "untrusted",
                },
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "pool": pool(
                    slowlog_timeout=10,
                    terminate_timeout=120,
                    memory_limit=256,
                    upload_max_filesize=64,
                    post_max_size=64,
                    max_children=8,
                ).document(),
            },
        )

    def test_an_out_of_bounds_value_is_refused_before_queueing(self) -> None:
        response = self.client.post(self.url, {"process_manager": "static", "max_children": "65"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/settings/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_viewer_cannot_change_php_settings(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(self.url, {"process_manager": "static", "max_children": "4"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_the_observed_pool_is_reconstructed_from_the_stored_snapshot(self) -> None:
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        self.assertEqual(snapshot.collected.sites.value[0].pool, SitePool())

    def test_the_settings_page_offers_the_observed_settings_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/settings/")
        self.assertContains(response, "PHP settings")
        self.assertContains(response, 'name="max_children"')
        self.assertContains(response, 'value="2"')
