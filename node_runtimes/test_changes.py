"""Node operator request authorization and concurrency (docs/node-runtimes-native-design.md)."""

from unittest.mock import Mock

from django.contrib.auth.models import Permission, User
from django.test import TestCase
from django.utils import timezone

from bootstrap.actions import BOOTSTRAP
from bootstrap.models import Action, PlanPreparation
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from operations.models import RemoteOperation
from servers.models import Server
from servers.testing import ControllerConfigTestCase, record_run

from . import catalog
from .changes import advance, request_runtime_change
from .handler import HANDLER
from .models import PlanNodeRuntime, RuntimeChange, RuntimeRequest
from .permissions import operation_required, required
from .services import request_runtime_preparation


class RequestTests(TestCase):
    def bootstrap_operator(self) -> User:
        user = User.objects.create_user("bootstrap-operator")
        for permission in {*BOOTSTRAP.prepare, *BOOTSTRAP.apply}:
            app, codename = permission.split(".")
            user.user_permissions.add(
                Permission.objects.get(content_type__app_label=app, codename=codename)
            )
        return user

    def test_bootstrap_authority_allows_default_but_cannot_change_existing_site(self) -> None:
        user = self.bootstrap_operator()
        server = Server.objects.create(name="Server", ssh_alias="server")
        self.assertIsNone(
            request_runtime_change(server, user.pk, catalog.DEFAULT, identifier="shop")
        )
        self.assertIsNone(
            request_runtime_preparation(server, user, catalog.DEFAULT, identifier="shop")
        )
        self.assertFalse(PlanPreparation.objects.exists())
        self.assertIsNotNone(request_runtime_change(server, user.pk, catalog.DEFAULT))

    def test_revoked_site_prepare_permission_stops_worker_before_native_read(self) -> None:
        user = self.bootstrap_operator()
        server = Server.objects.create(name="Server", ssh_alias="server")
        permission = Permission.objects.get(
            content_type__app_label="sites", codename="prepare_siteplan"
        )
        user.user_permissions.add(
            permission,
            Permission.objects.get(content_type__app_label="sites", codename="view_siteplan"),
        )
        preparation = request_runtime_preparation(server, user, catalog.DEFAULT, identifier="shop")
        self.assertIsNotNone(preparation)
        if preparation is None:
            self.fail("The authorized site review was not queued.")
        user.user_permissions.remove(permission)
        shell = Mock(spec=RemoteShell)
        with self.assertRaisesMessage(OperationRefused, "permission"):
            HANDLER.prepare(preparation, shell)
        shell.run.assert_not_called()

    def test_revoked_site_apply_permission_stops_intent_before_prerequisites(self) -> None:
        user = self.bootstrap_operator()
        for codename in ("view_siteplan", "prepare_siteplan", "apply_siteplan"):
            user.user_permissions.add(
                Permission.objects.get(content_type__app_label="sites", codename=codename)
            )
        server = Server.objects.create(name="Server", ssh_alias="server")
        change = request_runtime_change(server, user.pk, catalog.DEFAULT, identifier="shop")
        self.assertIsNotNone(change)
        if change is None:
            self.fail("The authorized site intent was not queued.")
        user.user_permissions.remove(
            Permission.objects.get(content_type__app_label="sites", codename="apply_siteplan")
        )
        advance.call(change.pk)
        change.refresh_from_db()
        self.assertEqual(change.status, "failed")
        self.assertFalse(change.steps.exists())

    def test_independent_apply_cannot_bypass_scoped_permission_with_cached_user(self) -> None:
        user = self.bootstrap_operator()
        server = Server.objects.create(name="Server", ssh_alias="server")
        preparation = PlanPreparation.objects.create(
            server=server, ssh_alias=server.ssh_alias, action=Action.NODE_RUNTIME
        )
        run = record_run(server, Action.NODE_RUNTIME, preparation=preparation)
        run.requested_by = user
        run.save(update_fields=["requested_by"])
        plan = run.plan
        if plan is None:
            self.fail("The independent reviewed plan is missing.")
        PlanNodeRuntime.objects.create(
            plan=plan,
            version=catalog.DEFAULT,
            identifier="shop",
            architecture="arm64",
            digest="a" * 64,
            executable=catalog.executable(catalog.DEFAULT),
            installs_runtime=True,
        )
        HANDLER.copy_audit(plan, run)
        permission = Permission.objects.get(
            content_type__app_label="sites", codename="apply_siteplan"
        )
        user.user_permissions.add(
            permission,
            Permission.objects.get(content_type__app_label="sites", codename="view_siteplan"),
        )
        self.assertTrue(user.has_perm("sites.apply_siteplan"))
        user.user_permissions.remove(permission)
        with self.assertRaisesMessage(OperationRefused, "permission"):
            HANDLER.payload(run, plan)
        shell = Mock(spec=RemoteShell)
        with self.assertRaisesMessage(OperationRefused, "permission"):
            HANDLER.admit(shell, run, root=True)
        shell.run.assert_not_called()

    def test_permission_denial_queues_nothing(self) -> None:
        user = User.objects.create_user("observer")
        server = Server.objects.create(name="Server", ssh_alias="server")
        self.assertIsNone(request_runtime_change(server, user.pk, catalog.DEFAULT))
        self.assertEqual(RuntimeChange.objects.count(), 0)

    def test_duplicate_intent_converges_and_conflicting_intent_refuses(self) -> None:
        user = User.objects.create_superuser("operator")
        server = Server.objects.create(name="Server", ssh_alias="server")
        first = request_runtime_change(server, user.pk, catalog.DEFAULT)
        self.assertIsNotNone(first)
        self.assertEqual(request_runtime_change(server, user.pk, catalog.DEFAULT), first)
        self.assertIsNone(request_runtime_change(server, user.pk, "22.23.3"))
        self.assertEqual(RuntimeChange.objects.count(), 1)

    def test_unresolved_or_injected_release_never_queues(self) -> None:
        user = User.objects.create_superuser("operator")
        server = Server.objects.create(name="Server", ssh_alias="server")
        for version in ("lts", "latest", "24.21.0; id"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                request_runtime_change(server, user.pk, version)
        self.assertEqual(RuntimeChange.objects.count(), 0)

    def test_removed_server_stops_pending_intent_without_blocking_removal(self) -> None:
        from .changes import advance

        user = User.objects.create_superuser("operator")
        server = Server.objects.create(name="Server", ssh_alias="server")
        change = request_runtime_change(server, user.pk, catalog.DEFAULT)
        self.assertIsNotNone(change)
        if change is None:
            self.fail("The intent was not queued.")
        server.delete()
        advance.call(change.pk)
        change.refresh_from_db()
        self.assertEqual(change.status, "failed")
        self.assertEqual(change.steps.count(), 0)


class ViewAuthorityTests(ControllerConfigTestCase):
    def reviewed(self, identifier: str) -> tuple[int, int]:
        self.grant(
            "view_server",
            "view_configurationplan",
            "prepare_configurationplan",
            "apply_configurationplan",
        )
        self.client.force_login(self.user)
        server = Server.objects.create(name="Server", ssh_alias="web.example.com")
        preparation = PlanPreparation.objects.create(
            server=server,
            ssh_alias=server.ssh_alias,
            action=Action.NODE_RUNTIME,
            status=RemoteOperation.Status.SUCCEEDED,
            finished_at=timezone.now(),
        )
        RuntimeRequest.objects.create(
            preparation=preparation, version=catalog.DEFAULT, identifier=identifier
        )
        run = record_run(server, Action.NODE_RUNTIME, preparation=preparation)
        plan = run.plan
        if plan is None:
            self.fail("The reviewed Node plan is missing.")
        PlanNodeRuntime.objects.create(
            plan=plan,
            version=catalog.DEFAULT,
            identifier=identifier,
            architecture="arm64",
            digest="a" * 64,
            executable=catalog.executable(catalog.DEFAULT),
            installs_runtime=True,
        )
        HANDLER.copy_audit(plan, run)
        return preparation.pk, run.pk

    def test_site_preparation_and_run_deny_bootstrap_only_viewers(self) -> None:
        preparation_id, run_id = self.reviewed("shop")
        for path in (
            f"/plans/{preparation_id}/",
            f"/applies/{run_id}/",
            f"/applies/{run_id}/status/",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 403)
        self.grant("view_siteplan")
        for path in (f"/plans/{preparation_id}/", f"/applies/{run_id}/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)
        self.assertFalse(self.client.get(f"/applies/{run_id}/").context["can_acknowledge"])
        plan = PlanPreparation.objects.get(pk=preparation_id).plan
        for path in (f"/plans/{plan.pk}/apply/", f"/applies/{run_id}/acknowledge/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.post(path, {"understood": "on"}).status_code, 403)

    def test_server_default_preparation_and_run_remain_visible(self) -> None:
        preparation_id, run_id = self.reviewed("")
        for path in (f"/plans/{preparation_id}/", f"/applies/{run_id}/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_scoped_authority_uses_request_or_retained_run_and_missing_type_refuses(self) -> None:
        preparation_id, run_id = self.reviewed("shop")
        self.assertEqual(operation_required(preparation_id, "view"), required("shop", "view"))
        self.assertEqual(operation_required(run_id, "apply"), required("shop", "apply"))
        RuntimeRequest.objects.filter(preparation_id=preparation_id).delete()
        self.assertIsNone(operation_required(preparation_id, "view"))
        self.assertEqual(operation_required(run_id, "view"), required("shop", "view"))
        self.assertEqual(self.client.get(f"/plans/{preparation_id}/").status_code, 403)
