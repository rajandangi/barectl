from unittest import mock

from django.db import IntegrityError, transaction

from . import lifecycle
from .fakes import ChangeTestCase
from .models import ChangePreparation
from .services import request_prepare


class PreparationInputTests(ChangeTestCase):
    def test_inputless_intent_is_versioned_and_cannot_be_rewritten(self) -> None:
        preparation = request_prepare(self.server, self.user, "cleanup_runs")
        self.assertIsNotNone(preparation)
        if preparation is None:
            self.fail("Preparation was not queued.")
        self.assertEqual(preparation.inputs, {"version": 1})
        preparation.inputs = {"version": 1, "selection": "php84"}
        with self.assertRaises(ValueError):
            preparation.save()
        with self.assertRaises(ValueError):
            ChangePreparation.objects.filter(pk=preparation.pk).update(kind_slug="add_runtime")

    def test_invalid_inputless_selection_is_refused_before_connecting(self) -> None:
        self.sign_in_with("view_server", "view_changes", "change_site")
        preparation = lifecycle.queue(
            ChangePreparation,
            self.server,
            requested_by=self.user,
            kind_slug="cleanup_runs",
            inputs={"version": 2},
        )
        with mock.patch("discovery.ssh.connect_operation") as connect:
            self.run_worker()
        preparation.refresh_from_db()
        self.assertEqual(preparation.status, "failed")
        self.assertIn("preparation inputs", preparation.failure)
        connect.assert_not_called()

    def test_existing_identity_cannot_replace_intent_through_a_fresh_constructor(self) -> None:
        preparation = request_prepare(self.server, self.user, "cleanup_runs")
        if preparation is None:
            self.fail("Preparation was not queued.")
        forged = ChangePreparation(
            pk=preparation.pk,
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            kind_slug="add_runtime",
            inputs={"version": 1, "selection": "php84"},
        )
        with self.assertRaises(IntegrityError), transaction.atomic():
            forged.save()
        with self.assertRaises(ValueError):
            ChangePreparation._base_manager.filter(pk=preparation.pk).update(inputs={"version": 2})
        preparation.refresh_from_db()
        self.assertEqual(preparation.kind_slug, "cleanup_runs")
        self.assertEqual(preparation.inputs, {"version": 1})


class SitePreparationEnvelopeTests(ChangeTestCase):
    def test_create_intent_is_copied_and_cannot_be_rewritten(self) -> None:
        from . import engine
        from .engine import ChangeKind, NativeBody, ReviewDraft, register_kind
        from .inputs import InputShape

        kind = ChangeKind(
            "fixture_create",
            "Create site",
            lambda shell, inputs: None,
            lambda evidence, inputs: ReviewDraft("fixture_create", "Create"),
            lambda document, context: NativeBody(b"exit 0"),
            lambda shell, review: True,
            input_choices=("php84", "php85"),
            input_shape=InputShape.SITE_CREATE,
        )
        register_kind(kind)
        self.addCleanup(engine._KINDS.pop, kind.slug, None)
        names = ["shop.example.com"]
        preparation = request_prepare(
            self.server,
            self.user,
            kind.slug,
            inputs={
                "version": 1,
                "identifier": "shop",
                "names": names,
                "selection": "php84",
            },
        )
        self.assertIsNotNone(preparation)
        if preparation is None:
            self.fail("No preparation was queued.")
        names.append("other.example.com")
        preparation.refresh_from_db()
        self.assertEqual(preparation.inputs["names"], ["shop.example.com"])

    def test_invalid_site_fields_never_open_ssh(self) -> None:
        from . import engine
        from .inputs import InputShape

        kind = engine.ChangeKind(
            "fixture_create",
            "Create site",
            lambda shell, inputs: None,
            lambda evidence, inputs: engine.ReviewDraft("fixture_create", "Create"),
            lambda document, context: engine.NativeBody(b"exit 0"),
            lambda shell, review: True,
            input_choices=("php84",),
            input_shape=InputShape.SITE_CREATE,
        )
        engine.register_kind(kind)
        self.addCleanup(engine._KINDS.pop, kind.slug, None)
        valid: dict[str, object] = {
            "version": 1,
            "identifier": "shop",
            "names": ["shop.example.com"],
            "selection": "php84",
        }
        for field, bad in (
            ("version", True),
            ("identifier", "repo"),
            ("names", ["UPPER.example.com"]),
            ("names", ["a.example.com a.other.com"]),
            ("selection", "/nix/store/evil"),
        ):
            with self.subTest(field=field, bad=bad):
                preparation = lifecycle.queue(
                    ChangePreparation,
                    self.server,
                    requested_by=self.user,
                    kind_slug=kind.slug,
                    inputs=valid | {field: bad},
                )
                with mock.patch("discovery.ssh.connect_operation") as connect:
                    self.run_worker()
                preparation.refresh_from_db()
                self.assertEqual(preparation.status, "failed")
                connect.assert_not_called()
