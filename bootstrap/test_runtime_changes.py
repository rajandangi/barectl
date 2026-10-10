"""Runtime controls retain authorization and fresh-worker execution boundaries."""

from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from discovery.fakes import FakeServer, run_worker
from operations.models import RemoteOperation
from servers.models import Server

from .fakes import UbuntuServer
from .models import Action, ApplyRun, Verification
from .releases import NOBLE
from .runtime_changes import request_php_default, request_site_php_switch
from .runtime_handler import HANDLER, RuntimeDraft, installation_draft
from .runtime_models import RuntimeChange, RuntimeRun
from .runtime_services import PhpDefault, PhpRuntimeObservation


class RuntimeControlsTests(TestCase):
    def test_library_phase_requires_fresh_absence_of_the_previously_absent_default(self) -> None:
        server = Server.objects.create(name="Native", ssh_alias="native")
        run = ApplyRun.objects.create(
            server=server,
            action=Action.PHP_DEFAULT,
            release="24.04",
            plan_number=1,
            profile_revision=12,
            admission_deadline_centiseconds=100,
            admission_expires_at=timezone.now(),
        )
        RuntimeRun.objects.create(run=run, branch="8.3", package_action=Action.PHP_LIBRARIES)
        appeared = PhpDefault("8.3", "/usr/bin/php8.3", "manual", "php8.3-cli", "8.3.35", "arm64")
        for observation, expected in (
            (PhpRuntimeObservation(supply="sury", fresh=True), Verification.PASSED),
            (PhpRuntimeObservation(default=appeared, supply="sury"), Verification.FAILED),
            (PhpRuntimeObservation(failure="Native read unavailable."), Verification.UNAVAILABLE),
        ):
            with (
                self.subTest(expected=expected),
                patch(
                    "bootstrap.runtime_handler.apply.verify_profile",
                    return_value=Verification.PASSED,
                ),
                patch(
                    "bootstrap.runtime_handler.runtime_services.observe_php_runtime",
                    return_value=observation,
                ),
            ):
                self.assertEqual(HANDLER.verify(FakeServer(), run), expected)

    def test_library_review_preserves_runtime_intent_without_a_php_package_selection(
        self,
    ) -> None:
        shell = FakeServer()
        UbuntuServer().answer(shell)
        draft = RuntimeDraft(
            Action.SITE_PHP_SWITCH,
            "Switch the installed application.",
            None,
            NOBLE,
            branch="8.4",
            php_version="8.4",
            php_supply="sury",
            source_digest="a" * 64,
            before_branch="8.3",
        )
        result = installation_draft(shell, draft, Action.WORDPRESS_LIBRARIES)
        self.assertEqual(result.package_action, Action.WORDPRESS_LIBRARIES)
        self.assertEqual(result.branch, "8.4")
        self.assertEqual(result.source_digest, "a" * 64)
        self.assertEqual(result.before_branch, "8.3")
        self.assertEqual((result.php_version, result.php_supply), ("", "ubuntu"))

    def test_unprivileged_request_and_revoked_queued_intent_never_connect(self) -> None:
        user = User.objects.create_user("viewer")
        server = Server.objects.create(name="Native", ssh_alias="native")
        self.assertIsNone(request_php_default(server, user, "8.4"))
        self.assertIsNone(request_site_php_switch(server, user, "alpha", "8.4"))
        self.assertFalse(RemoteOperation.objects.exists())
        user.is_superuser = True
        user.save(update_fields=["is_superuser"])
        # Permission caches belong to this account instance, not queued authorization.
        user = User.objects.get(pk=user.pk)
        change = request_php_default(server, user, "8.4")
        self.assertIsNotNone(change)
        again = request_php_default(server, user, "8.4")
        self.assertEqual(change, again)
        user.is_active = False
        user.save(update_fields=["is_active"])
        shell = FakeServer()
        with shell.substituted():
            run_worker()
        self.assertEqual(shell.commands, [])
        if change is not None:
            change.refresh_from_db()
            self.assertEqual(change.status, RuntimeChange.Status.FAILED)
            self.assertIn("authorization", change.failure)
        self.assertFalse(RemoteOperation.objects.exists())
