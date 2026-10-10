"""Hosting intent authorization, dependency advancement and uncertain outcomes."""

from dataclasses import replace
from datetime import timedelta
from typing import override
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from bootstrap.apply import ApplyRequest
from bootstrap.models import Action, ConfigurationPlan, PlanPreparation, Privilege, Verification
from bootstrap.source_tools_models import SourceToolsSelection
from discovery.fakes import COLLECTED, COLLECTED_AT
from discovery.models import DiscoveryAttempt
from discovery.snapshot import save_snapshot
from operations.models import RemoteOperation
from servers.models import Server
from servers.registration import RemovalBlocked, remove_server
from servers.testing import record_run

from .creation import CreationInput, advance_creation, completed, read_creation, request_creation
from .models import HostingCreation, HostingCreationStep

HOST_KEY = "ssh-ed25519 SHA256:sitecreation"


class CreationTests(TestCase):
    @override
    def setUp(self) -> None:
        self.user = User.objects.create_superuser("operator", "ops@example.com", "local-password")
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.discovery = self.observe()
        self.wanted = CreationInput(
            ("shop.example.com",), discovery_revision=self.discovery.snapshot.pk
        )
        self.enterContext(patch("hosting.creation.advance_creation"))
        self.php = self.enterContext(
            patch(
                "hosting.creation.request_php_installation",
                side_effect=lambda *args: self.prepare(Action.PHP),
            )
        )
        self.enterContext(patch("hosting.creation.queue_discovery", side_effect=self.observe))

    def observe(self, server: Server | None = None) -> DiscoveryAttempt:
        attempt = DiscoveryAttempt.objects.create(
            server=server or self.server,
            ssh_alias=self.server.ssh_alias,
            host_key=HOST_KEY,
            status=RemoteOperation.Status.SUCCEEDED,
            finished_at=timezone.now(),
        )
        save_snapshot(attempt, COLLECTED, COLLECTED_AT)
        return attempt

    def create(self, wanted: CreationInput | None = None) -> HostingCreation:
        created = request_creation(self.server, self.user.pk, wanted or self.wanted)
        if created is None:
            raise AssertionError("The hosting intent was refused.")
        return created

    def prepare(
        self,
        stage: str,
        *,
        no_changes: bool = True,
        supply: str = "ubuntu",
        installed: bool = False,
    ) -> PlanPreparation:
        preparation = PlanPreparation.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            action=stage,
            requested_by=self.user,
            host_key=HOST_KEY,
            status=RemoteOperation.Status.SUCCEEDED,
            finished_at=timezone.now(),
        )
        plan = ConfigurationPlan.objects.create(
            preparation=preparation,
            action=stage,
            profile_revision=1,
            intent="Prepare the selected hosting prerequisite",
            eligible=True,
            no_changes=no_changes,
            ssh_alias=self.server.ssh_alias,
            host_key=HOST_KEY,
            boot_id="6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23",
            uptime_centiseconds=1000,
            admission_deadline_centiseconds=91000,
            collected_at=timezone.now(),
            admission_expires_at=timezone.now() + timedelta(minutes=15),
            privilege=Privilege.ROOT,
            release="24.04",
            architecture="arm64",
        )
        if stage == Action.PHP_SOURCE_PREREQUISITES:
            SourceToolsSelection.objects.create(
                plan=plan,
                supply=supply,
                installed=installed,
                default_branch="",
                fingerprint="a" * 64,
            )
        return preparation

    def advance(self, creation: HostingCreation) -> None:
        advance_creation.call(creation.pk)
        creation.refresh_from_db()

    def test_duplicate_intent_has_one_record_and_no_remote_work(self) -> None:
        with patch("hosting.creation.queue_discovery") as discover:
            first = self.create()
            self.assertEqual(self.create().pk, first.pk)
            self.assertEqual(HostingCreation.objects.count(), 1)
            self.assertFalse(HostingCreationStep.objects.exists())
            discover.assert_not_called()

    def test_stale_observation_and_a_different_account_cannot_authorize_an_intent(self) -> None:
        self.assertIsNone(
            request_creation(
                self.server, self.user.pk, replace(self.wanted, discovery_revision=0 + 9999)
            )
        )
        first = self.create()
        other = User.objects.create_superuser("other", "other@example.com", "local-password")
        self.assertIsNone(request_creation(self.server, other.pk, self.wanted))
        self.assertEqual(HostingCreation.objects.get().pk, first.pk)

    def test_ordinary_php_creation_has_no_application_database_or_certificate_stage(self) -> None:
        creation = self.create()
        with (
            patch(
                "hosting.creation.request_preparation",
                side_effect=lambda server, user, action, **kwargs: self.prepare(action),
            ) as bootstrap,
            patch(
                "hosting.creation.request_site_preparation",
                side_effect=lambda *args, **kwargs: self.prepare(Action.SITE_HTTP),
            ) as site,
        ):
            for _ in range(20):
                self.advance(creation)
                if creation.status != HostingCreation.Status.ACTIVE:
                    break
        self.assertEqual(creation.status, HostingCreation.Status.SUCCEEDED)
        self.assertEqual(creation.php_version, "8.3")
        stages = tuple(creation.steps.values_list("stage", flat=True))
        self.assertNotIn(Action.WPCLI, stages)
        self.assertNotIn(Action.WORDPRESS_INSTALL, stages)
        self.assertNotIn(Action.MARIADB, stages)
        self.assertNotIn(Action.CERTBOT, stages)
        self.assertNotIn(
            Action.PHP_SOURCE, tuple(call.args[2] for call in bootstrap.call_args_list)
        )
        site.assert_called_once()
        self.php.assert_called_once_with(self.server, self.user, "8.3", "ubuntu")
        self.assertEqual(site.call_args.kwargs["php_version"], "8.3")
        self.assertEqual(site.call_args.kwargs["convention_revision"], 4)
        view = read_creation(self.server)
        self.assertIsNotNone(view)
        if view is not None:
            self.assertTrue(all(step.status == "succeeded" for step in view.steps))

    def test_existing_php_source_is_retained_without_converting_its_repository(self) -> None:
        creation = self.create(replace(self.wanted, php_version="8.3"))
        with patch(
            "hosting.creation.request_preparation",
            side_effect=lambda server, user, action, **kwargs: self.prepare(
                action, supply="sury", installed=True
            ),
        ) as bootstrap:
            for _ in range(8):
                self.advance(creation)
        self.assertEqual(creation.php_supply, "sury")
        self.assertFalse(creation.source_setup_needed)
        self.assertNotIn(
            Action.PHP_SOURCE, tuple(call.args[2] for call in bootstrap.call_args_list)
        )

    def test_fresh_sury_creation_queues_source_before_php_with_selected_supply(self) -> None:
        creation = self.create()
        with patch(
            "hosting.creation.request_preparation",
            side_effect=lambda server, user, action, **kwargs: self.prepare(action, supply="sury"),
        ) as bootstrap:
            for _ in range(10):
                self.advance(creation)
        calls = bootstrap.call_args_list
        actions = tuple(call.args[2] for call in calls)
        stages = tuple(creation.steps.values_list("stage", flat=True))
        self.assertIn(Action.PHP_SOURCE, actions)
        self.assertLess(stages.index(Action.PHP_SOURCE), stages.index(Action.PHP))
        self.assertLess(stages.index(Action.PHP_LIBRARIES), stages.index(Action.PHP))
        self.assertIn(Action.PHP_LIBRARIES, actions)
        self.php.assert_called_once_with(self.server, self.user, "8.3", "sury")

    def test_revocation_or_connection_change_stops_before_discovery(self) -> None:
        for change in ("permission", "connection"):
            with self.subTest(change=change):
                creation = self.create(replace(self.wanted, names=(f"{change}.example.com",)))
                if change == "permission":
                    User.objects.filter(pk=self.user.pk).update(is_active=False)
                else:
                    Server.objects.filter(pk=self.server.pk).update(ssh_alias="different")
                self.advance(creation)
                self.assertEqual(creation.status, HostingCreation.Status.FAILED)
                self.assertFalse(creation.steps.exists())
                User.objects.filter(pk=self.user.pk).update(is_active=True)

    def test_active_creation_blocks_removal_between_component_operations(self) -> None:
        self.create()
        with self.assertRaises(RemovalBlocked):
            remove_server(self.server)

    def test_unqualified_wordpress_stops_before_source_tools_apply(self) -> None:
        wanted = replace(
            self.wanted,
            application="wordpress",
            title="Shop",
            admin_login="owner",
            admin_email="ops@example.com",
        )
        creation = self.create(wanted)
        preparation = self.prepare(Action.PHP_SOURCE_PREREQUISITES, no_changes=False, supply="sury")
        HostingCreationStep.objects.create(
            creation=creation,
            position=2,
            stage=Action.PHP_SOURCE_PREREQUISITES,
            preparation=preparation,
        )
        with (
            patch("wordpress.qualification.SOURCE_COMBINATIONS", ()),
            patch("hosting.creation.request_apply") as apply,
        ):
            self.advance(creation)
            apply.assert_not_called()
        self.assertEqual(creation.status, HostingCreation.Status.FAILED)
        self.assertIn("qualified", creation.failure)

    def test_uncertain_apply_is_never_replayed_and_verified_failure_stops(self) -> None:
        creation = self.create()
        preparation = self.prepare(Action.NGINX, no_changes=False)
        step = HostingCreationStep.objects.create(
            creation=creation, position=5, stage=Action.NGINX, preparation=preparation
        )
        run = record_run(self.server, Action.NGINX, status=RemoteOperation.Status.RECONCILING)
        run.host_key = HOST_KEY
        run.save(update_fields=["host_key"])
        step.run = run
        step.save(update_fields=["run"])
        with patch("hosting.creation.request_apply") as apply:
            self.advance(creation)
            self.advance(creation)
            apply.assert_not_called()
        self.assertEqual(creation.status, HostingCreation.Status.ACTIVE)
        self.assertEqual(creation.steps.count(), 1)
        run.status = RemoteOperation.Status.SUCCEEDED
        run.verification = Verification.FAILED
        run.save(update_fields=["status", "verification"])
        self.advance(creation)
        self.assertEqual(creation.status, HostingCreation.Status.FAILED)

    def test_apply_refresh_discovery_pauses_then_rejoins_through_completion(self) -> None:
        creation = self.create()
        preparation = self.prepare(Action.NGINX, no_changes=False)
        step = HostingCreationStep.objects.create(
            creation=creation, position=5, stage=Action.NGINX, preparation=preparation
        )
        run = record_run(self.server, Action.NGINX)
        run.host_key = HOST_KEY
        run.save(update_fields=["host_key"])
        step.run = run
        step.save(update_fields=["run"])
        refreshing = DiscoveryAttempt.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            status=RemoteOperation.Status.RUNNING,
            started_at=timezone.now(),
        )
        with patch("hosting.creation.request_preparation") as prepare:
            self.advance(creation)
            prepare.assert_not_called()
        self.assertEqual(creation.status, HostingCreation.Status.ACTIVE)
        refreshing.status = RemoteOperation.Status.SUCCEEDED
        refreshing.host_key = HOST_KEY
        refreshing.save(update_fields=["status", "host_key"])
        with patch("hosting.creation.advance_creation.enqueue") as enqueue:
            completed([refreshing.pk])
            enqueue.assert_called_once_with(creation.pk)
        with patch(
            "hosting.creation.request_preparation",
            side_effect=lambda server, user, action, **kwargs: self.prepare(action),
        ) as prepare:
            self.advance(creation)
            self.advance(creation)
            prepare.assert_not_called()
            self.php.assert_called_once_with(self.server, self.user, "", "")

    def test_prepared_mutation_gets_one_existing_apply_request(self) -> None:
        creation = self.create()
        preparation = self.prepare(Action.NGINX, no_changes=False)
        HostingCreationStep.objects.create(
            creation=creation, position=5, stage=Action.NGINX, preparation=preparation
        )
        with patch(
            "hosting.creation.request_apply",
            side_effect=lambda plan, user: ApplyRequest(
                record_run(self.server, Action.NGINX, status=RemoteOperation.Status.QUEUED)
            ),
        ) as apply:
            self.advance(creation)
            self.advance(creation)
            apply.assert_called_once()
        self.assertEqual(creation.steps.count(), 1)

    def test_explicit_wordpress_uses_existing_prerequisites_and_install_service(self) -> None:
        wanted = replace(
            self.wanted,
            application="wordpress",
            title="Shop",
            admin_login="owner",
            admin_email="ops@example.com",
        )
        creation = self.create(wanted)
        services = (
            "request_preparation",
            "request_site_preparation",
            "request_driver_preparation",
            "request_binding_preparation",
            "request_runtime_preparation",
            "request_setup_preparation",
            "request_challenge_preparation",
            "request_issuance_preparation",
            "request_activation_preparation",
            "request_wpcli_preparation",
            "request_install_preparation",
        )
        actions = (
            None,
            Action.SITE_HTTP,
            None,
            Action.DATABASE_MARIADB,
            Action.PHP_WORDPRESS,
            Action.CERTBOT,
            Action.TLS_CHALLENGE,
            Action.TLS_ISSUANCE,
            Action.TLS_ACTIVATION,
            Action.WPCLI,
            Action.WORDPRESS_INSTALL,
        )
        install = None
        for name, action in zip(services, actions, strict=True):

            def prepared(
                *args: object, selected: Action | None = action, **kwargs: object
            ) -> PlanPreparation:
                return self.prepare(str(args[2]) if selected is None else selected)

            service = self.enterContext(patch(f"hosting.creation.{name}", side_effect=prepared))
            if name == "request_install_preparation":
                install = service
        for _ in range(30):
            self.advance(creation)
            if creation.status != HostingCreation.Status.ACTIVE:
                break
        self.assertEqual(creation.status, HostingCreation.Status.SUCCEEDED)
        stages = tuple(creation.steps.values_list("stage", flat=True))
        self.assertLess(stages.index(Action.WORDPRESS_LIBRARIES), stages.index(Action.PHP))
        self.assertLess(
            stages.index(Action.DATABASE_MARIADB), stages.index(Action.WORDPRESS_INSTALL)
        )
        self.assertLess(stages.index(Action.TLS_ACTIVATION), stages.index(Action.WORDPRESS_INSTALL))
        if install is None:
            raise AssertionError("No installer seam was registered.")
        install.assert_called_once()
        metadata = install.call_args.args[3]
        self.assertEqual(metadata.canonical_name, wanted.names[0])
        self.assertEqual(metadata.title, wanted.title)
        self.assertEqual(metadata.admin_login, wanted.admin_login)
        self.assertNotIn(Action.WORDPRESS_FINISH, stages)

    def test_failed_auto_discovery_and_changed_identity_stop_before_next_package(self) -> None:
        for failed in (True, False):
            with self.subTest(failed=failed):
                current = self.observe()
                creation = self.create(
                    replace(
                        self.wanted,
                        names=(f"site{int(failed)}.example.com",),
                        discovery_revision=current.snapshot.pk,
                    )
                )
                preparation = self.prepare(Action.NGINX)
                HostingCreationStep.objects.create(
                    creation=creation, position=5, stage=Action.NGINX, preparation=preparation
                )
                latest = self.observe()
                latest.status = (
                    RemoteOperation.Status.FAILED if failed else RemoteOperation.Status.SUCCEEDED
                )
                latest.host_key = HOST_KEY if failed else "ssh-ed25519 SHA256:changed"
                latest.save(update_fields=["status", "host_key"])
                with patch("hosting.creation.request_preparation") as queued:
                    self.advance(creation)
                    queued.assert_not_called()
                self.assertEqual(creation.status, HostingCreation.Status.FAILED)
                self.observe()
