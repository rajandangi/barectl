"""Saved-address checks through the dashboard, worker and real SSH negotiation."""

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import override
from unittest import mock

from django.test import TransactionTestCase, override_settings
from paramiko import ECDSAKey

from servers.testing import ControllerConfigTestCase

from .fakes import run_worker
from .models import DiscoveryAttempt
from .ssh_testing import USER, SshServer


class SavedTransportTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        self.client_key = ECDSAKey.generate()
        self.host_key = ECDSAKey.generate()
        self.remote = SshServer(self.host_key, self.client_key)
        self.addCleanup(self.remote.close)
        self.trust = self.directory / "known_hosts"
        self.trust.write_text(
            f"[127.0.0.1]:{self.remote.port} {self.host_key.get_name()} "
            f"{self.host_key.get_base64()}\n"
        )
        self.key_file = self.directory / "id_ecdsa"
        self.client_key.write_private_key_file(str(self.key_file))
        self.enterContext(override_settings(SSH_KNOWN_HOSTS_PATH=str(self.trust)))
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)

    def start_agent(self, *, load_key: bool = True) -> None:
        socket = self.directory / "agent"
        agent = subprocess.Popen(  # noqa: S603
            ["ssh-agent", "-D", "-a", str(socket)],  # noqa: S607
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(agent.wait)
        self.addCleanup(agent.terminate)
        deadline = time.monotonic() + 5
        while not socket.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        os.environ["SSH_AUTH_SOCK"] = str(socket)
        if load_key:
            subprocess.run(  # noqa: S603
                ["ssh-add", str(self.key_file)],  # noqa: S607
                check=True,
                capture_output=True,
            )

    def check(self, *, username: str = USER, reference: str = "") -> DiscoveryAttempt:
        response = self.client.post(
            "/servers/add/",
            {
                "name": "Cloud",
                "address": "127.0.0.1",
                "username": username,
                "credential_reference": reference,
                "credential_catalogue": self.selection_token(),
                "port": str(self.remote.port),
            },
        )
        self.assertEqual(response.status_code, 302)
        run_worker()
        return DiscoveryAttempt.objects.get()

    def test_empty_agent_reports_unavailable_credential(self) -> None:
        self.start_agent(load_key=False)
        result = self.check()
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("credential is unavailable", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_unknown_identity_is_refused_before_authentication(self) -> None:
        self.start_agent()
        self.trust.write_text("")
        result = self.check()
        self.assertIn("identity not yet trusted", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_provider_fingerprint_confirms_captured_key_and_continues(self) -> None:
        self.grant("change_server")
        self.start_agent()
        self.trust.write_text("")
        attempt = self.check()
        self.assertEqual(self.remote.auth_attempts, 0)
        page = self.client.get(f"/servers/{attempt.server_id}/")
        self.assertContains(page, self.host_key.fingerprint)
        response = self.client.post(
            f"/servers/{attempt.server_id}/confirm-host/",
            {"attempt": attempt.pk, "revision": 1, "fingerprint": self.host_key.fingerprint},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.trust.read_text(),
            (
                f"[127.0.0.1]:{self.remote.port} {self.host_key.get_name()} "
                f"{self.host_key.get_base64()}\n"
            ),
        )
        run_worker()
        result = DiscoveryAttempt.objects.latest("pk")
        self.assertEqual(result.status, DiscoveryAttempt.Status.SUCCEEDED, result.failure)

    def test_wrong_provider_fingerprint_never_writes_trust(self) -> None:
        self.grant("change_server")
        self.start_agent()
        self.trust.write_text("")
        attempt = self.check()
        for fingerprint in (
            "",
            "SHA256:not-a-fingerprint",
            ECDSAKey.generate().fingerprint,
            self.host_key.fingerprint + " ",
        ):
            with self.subTest(fingerprint=fingerprint):
                response = self.client.post(
                    f"/servers/{attempt.server_id}/confirm-host/",
                    {"attempt": attempt.pk, "revision": 1, "fingerprint": fingerprint},
                )
                self.assertEqual(response.status_code, 409)
                self.assertEqual(self.trust.read_text(), "")
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_confirmation_requires_editor_permission_and_csrf(self) -> None:
        from django.test import Client

        self.trust.write_text("")
        attempt = self.check()
        endpoint = f"/servers/{attempt.server_id}/confirm-host/"
        data = {"attempt": attempt.pk, "revision": 1, "fingerprint": self.host_key.fingerprint}
        self.assertEqual(self.client.post(endpoint, data).status_code, 403)
        self.grant("change_server")
        protected = Client(enforce_csrf_checks=True)
        protected.force_login(self.user)
        self.assertEqual(protected.post(endpoint, data).status_code, 403)
        self.assertEqual(self.trust.read_text(), "")

    def test_confirmation_refuses_trust_changed_since_probe(self) -> None:
        self.grant("change_server")
        self.trust.write_text("")
        attempt = self.check()
        other = ECDSAKey.generate()
        changed = f"[127.0.0.1]:{self.remote.port} {other.get_name()} {other.get_base64()}\n"
        for current in (
            changed,
            (
                f"@revoked [127.0.0.1]:{self.remote.port} "
                f"{self.host_key.get_name()} {self.host_key.get_base64()}\n"
            ),
        ):
            with self.subTest(current=current):
                self.trust.write_text(current)
                response = self.client.post(
                    f"/servers/{attempt.server_id}/confirm-host/",
                    {
                        "attempt": attempt.pk,
                        "revision": 1,
                        "fingerprint": self.host_key.fingerprint,
                    },
                )
                self.assertEqual(response.status_code, 409)
                self.assertEqual(self.trust.read_text(), current)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_stale_revision_confirmation_is_refused(self) -> None:
        self.grant("change_server")
        self.trust.write_text("")
        attempt = self.check()
        response = self.client.post(
            f"/servers/{attempt.server_id}/confirm-host/",
            {"attempt": attempt.pk, "revision": 2, "fingerprint": self.host_key.fingerprint},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.trust.read_text(), "")

    def test_browser_key_and_endpoint_cannot_replace_the_captured_challenge(self) -> None:
        self.grant("change_server")
        self.trust.write_text("# preserve unrelated controller entries\n")
        attempt = self.check()
        other = ECDSAKey.generate()
        response = self.client.post(
            f"/servers/{attempt.server_id}/confirm-host/",
            {
                "attempt": attempt.pk,
                "revision": 1,
                "fingerprint": self.host_key.fingerprint,
                "key_blob": other.get_base64(),
                "address": "attacker.example",
                "port": 22,
                "known_hosts": str(self.directory / "browser-selected"),
            },
        )
        self.assertEqual(response.status_code, 302)
        trust = self.trust.read_text()
        self.assertTrue(trust.startswith("# preserve unrelated controller entries\n"))
        self.assertIn(self.host_key.get_base64(), trust)
        self.assertNotIn(other.get_base64(), trust)
        self.assertNotIn("attacker.example", trust)
        self.assertFalse((self.directory / "browser-selected").exists())

    def test_key_rotation_after_confirmation_refuses_before_authentication(self) -> None:
        self.grant("change_server")
        self.start_agent()
        self.trust.write_text("")
        attempt = self.check()
        response = self.client.post(
            f"/servers/{attempt.server_id}/confirm-host/",
            {"attempt": attempt.pk, "revision": 1, "fingerprint": self.host_key.fingerprint},
        )
        self.assertEqual(response.status_code, 302)
        self.remote.host_key = ECDSAKey.generate()
        run_worker()
        result = DiscoveryAttempt.objects.latest("pk")
        self.assertIn("different host key", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)
        self.assertNotContains(
            self.client.get(f"/servers/{attempt.server_id}/"), "Confirm fingerprint and check"
        )

    def test_confirmed_identity_cannot_be_replaced_in_trust_before_dispatch(self) -> None:
        self.grant("change_server")
        self.start_agent()
        self.trust.write_text("")
        attempt = self.check()
        response = self.client.post(
            f"/servers/{attempt.server_id}/confirm-host/",
            {"attempt": attempt.pk, "revision": 1, "fingerprint": self.host_key.fingerprint},
        )
        self.assertEqual(response.status_code, 302)
        replacement = ECDSAKey.generate()
        self.remote.host_key = replacement
        self.trust.write_text(
            f"[127.0.0.1]:{self.remote.port} {replacement.get_name()} {replacement.get_base64()}\n"
        )
        run_worker()
        result = DiscoveryAttempt.objects.latest("pk")
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED, result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)
        self.assertNotContains(
            self.client.get(f"/servers/{attempt.server_id}/"), "Confirm fingerprint and check"
        )

    def test_agent_authenticates_without_forwarding(self) -> None:
        self.start_agent()
        result = self.check()
        self.assertEqual(result.status, DiscoveryAttempt.Status.SUCCEEDED, result.failure)
        self.assertEqual(self.remote.refused, [])

    def test_file_identity_is_not_a_fallback_for_an_empty_agent(self) -> None:
        self.start_agent(load_key=False)
        self.write_config(
            f"Host *\n  IdentityFile {self.key_file}\n  UserKnownHostsFile {self.trust}\n"
        )
        default_directory = self.directory / ".ssh"
        default_directory.mkdir()
        self.client_key.write_private_key_file(str(default_directory / "id_ecdsa"))
        with mock.patch.dict(os.environ, {"HOME": str(self.directory)}):
            result = self.check()
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_revoked_identity_is_refused_before_authentication(self) -> None:
        self.start_agent()
        self.trust.write_text("@revoked " + self.trust.read_text())
        result = self.check()
        self.assertIn("revoked", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)
        self.assertNotContains(
            self.client.get(f"/servers/{result.server_id}/"), "Confirm fingerprint and check"
        )

    def test_changed_identity_is_refused_before_authentication(self) -> None:
        self.start_agent()
        other = ECDSAKey.generate()
        self.trust.write_text(
            f"[127.0.0.1]:{self.remote.port} {other.get_name()} {other.get_base64()}\n"
        )
        result = self.check()
        self.assertIn("different host key", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_alias_cannot_bypass_revocation_in_the_owned_trust_file(self) -> None:
        alias_trust = self.directory / "alias_trust"
        alias_trust.write_text(self.trust.read_text())
        self.write_config(
            f"Host cloud\n  HostName 127.0.0.1\n  Port {self.remote.port}\n"
            f"  User {USER}\n  IdentityFile {self.key_file}\n  UserKnownHostsFile {alias_trust}\n"
        )
        self.trust.write_text("@revoked " + self.trust.read_text())
        response = self.client.post("/servers/add/", {"name": "Cloud", "ssh_alias": "cloud"})
        self.assertEqual(response.status_code, 302)
        run_worker()
        self.assertIn("revoked", DiscoveryAttempt.objects.get().failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_unreachable_server_has_a_distinct_sanitized_failure(self) -> None:
        self.remote.close()
        result = self.check()
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("could not reach the SSH service", result.failure)
        self.assertNotIn(str(self.directory), result.failure)

    def test_rejected_agent_key_has_a_distinct_authentication_failure(self) -> None:
        self.start_agent()
        result = self.check(username="wrong-user")
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("rejected the SSH credentials", result.failure)
        self.assertGreater(self.remote.auth_attempts, 0)

    def test_selected_file_is_the_only_offered_identity(self) -> None:
        other = ECDSAKey.generate()
        agent_file = self.directory / "agent-key"
        other.write_private_key_file(str(agent_file))
        original = self.key_file
        self.key_file = agent_file
        self.start_agent()
        self.key_file = original
        self.remote.additional_authorized = (other,)
        with override_settings(SSH_APPROVED_KEYS={"approved": str(original)}):
            result = self.check(reference="approved")
        self.assertEqual(result.status, DiscoveryAttempt.Status.SUCCEEDED, result.failure)
        self.assertEqual(self.remote.offered, [self.client_key])

    def test_removed_file_cannot_fall_back_to_an_accepted_agent(self) -> None:
        self.start_agent()
        with override_settings(SSH_APPROVED_KEYS={"approved": str(self.key_file)}):
            response = self.client.post(
                "/servers/add/",
                {
                    "name": "Cloud",
                    "address": "127.0.0.1",
                    "username": USER,
                    "port": self.remote.port,
                    "credential_reference": "approved",
                    "credential_catalogue": self.selection_token(),
                },
            )
            self.assertEqual(response.status_code, 302)
            self.key_file.unlink()
            run_worker()
        result = DiscoveryAttempt.objects.get()
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("credential is unavailable", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_replaced_and_unreadable_files_are_unavailable_at_dispatch(self) -> None:
        for change in ("replace", "unreadable", "unapprove"):
            with self.subTest(change=change):
                from servers.models import Server
                from servers.registration import remove_server

                for server in Server.objects.all():
                    remove_server(server)
                self.key_file.chmod(0o600)
                self.client_key.write_private_key_file(str(self.key_file))
                with override_settings(SSH_APPROVED_KEYS={"approved": str(self.key_file)}):
                    response = self.client.post(
                        "/servers/add/",
                        {
                            "name": "Cloud",
                            "address": "127.0.0.1",
                            "username": USER,
                            "port": self.remote.port,
                            "credential_reference": "approved",
                            "credential_catalogue": self.selection_token(),
                        },
                    )
                    self.assertEqual(response.status_code, 302)
                    if change == "replace":
                        replacement = self.directory / "replacement"
                        self.client_key.write_private_key_file(str(replacement))
                        replacement.replace(self.key_file)
                    elif change == "unreadable":
                        self.key_file.chmod(0)
                    else:
                        with override_settings(SSH_APPROVED_KEYS={}):
                            run_worker()
                    if change != "unapprove":
                        run_worker()
                result = DiscoveryAttempt.objects.get()
                self.assertIn("credential is unavailable", result.failure)
                self.assertEqual(self.remote.auth_attempts, 0)

    def test_rejected_file_reports_authentication_failure_without_agent_fallback(self) -> None:
        self.start_agent()
        other = ECDSAKey.generate()
        other.write_private_key_file(str(self.key_file))
        with override_settings(SSH_APPROVED_KEYS={"approved": str(self.key_file)}):
            result = self.check(reference="approved")
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("rejected the SSH credentials", result.failure)
        self.assertEqual(self.remote.offered, [other])

    def test_adjacent_certificate_is_never_imported_for_selected_file(self) -> None:
        Path(str(self.key_file) + "-cert.pub").write_text("invalid certificate")
        with override_settings(SSH_APPROVED_KEYS={"approved": str(self.key_file)}):
            result = self.check(reference="approved")
        self.assertEqual(result.status, DiscoveryAttempt.Status.SUCCEEDED, result.failure)
        self.assertEqual(self.remote.offered, [self.client_key])

    def selection_token(self) -> str:
        response = self.client.get("/servers/add/")
        return str(response.context["form"]["credential_catalogue"].value())

    def test_confirmed_approved_key_continuation_uses_only_selected_identity(self) -> None:
        self.grant("change_server")
        self.trust.write_text("")
        with override_settings(SSH_APPROVED_KEYS={"approved": str(self.key_file)}):
            attempt = self.check(reference="approved")
            self.assertEqual(self.remote.offered, [])
            response = self.client.post(
                f"/servers/{attempt.server_id}/confirm-host/",
                {"attempt": attempt.pk, "revision": 1, "fingerprint": self.host_key.fingerprint},
            )
            self.assertEqual(response.status_code, 302)
            run_worker()
        result = DiscoveryAttempt.objects.latest("pk")
        self.assertEqual(result.status, DiscoveryAttempt.Status.SUCCEEDED, result.failure)
        self.assertEqual(self.remote.offered, [self.client_key])

    def test_confirmed_approved_key_refuses_rotated_endpoint_and_trust_before_auth(self) -> None:
        self.grant("change_server")
        self.trust.write_text("")
        with override_settings(SSH_APPROVED_KEYS={"approved": str(self.key_file)}):
            attempt = self.check(reference="approved")
            response = self.client.post(
                f"/servers/{attempt.server_id}/confirm-host/",
                {"attempt": attempt.pk, "revision": 1, "fingerprint": self.host_key.fingerprint},
            )
            self.assertEqual(response.status_code, 302)
            replacement = ECDSAKey.generate()
            self.remote.host_key = replacement
            self.trust.write_text(
                f"[127.0.0.1]:{self.remote.port} {replacement.get_name()} "
                f"{replacement.get_base64()}\n"
            )
            run_worker()
        result = DiscoveryAttempt.objects.latest("pk")
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED, result.failure)
        self.assertEqual(self.remote.offered, [])


class ConcurrentConfirmationTests(TransactionTestCase):
    def test_concurrent_confirmations_cannot_trust_two_keys_for_one_endpoint(self) -> None:
        from concurrent.futures import ThreadPoolExecutor

        from django.contrib.auth.models import Permission, User
        from django.db import close_old_connections
        from django.test import Client

        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        if os.environ.get("BARECTL_CONFIRMATION_RACE_CHILD") != "1":
            result = subprocess.run(
                [
                    sys.executable,
                    "manage.py",
                    "test",
                    "discovery.test_saved_transport.ConcurrentConfirmationTests",
                    "--noinput",
                ],
                env=os.environ
                | {
                    "BARECTL_CONFIRMATION_RACE_CHILD": "1",
                    "BARECTL_TEST_DATABASE": str(directory / "race.sqlite3"),
                },
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return
        trust = directory / "known_hosts"
        trust.write_text("")
        config = directory / "config"
        config.write_text("")
        from dashboard.testing import TEST_MANIFEST

        self.enterContext(
            override_settings(
                SSH_KNOWN_HOSTS_PATH=str(trust),
                SSH_CONFIG_PATH=str(config),
                VITE_MANIFEST_PATH=TEST_MANIFEST,
            )
        )
        user = User.objects.create_user("operator")
        user.user_permissions.set(
            Permission.objects.filter(
                codename__in=("view_server", "add_server", "change_server", "add_discoveryattempt")
            )
        )
        first_key, second_key = ECDSAKey.generate(), ECDSAKey.generate()
        remote = SshServer(first_key, ECDSAKey.generate())
        self.addCleanup(remote.close)
        clients = (Client(), Client())
        for client in clients:
            client.force_login(user)
        attempts = []
        for index, host_key in enumerate((first_key, second_key)):
            remote.host_key = host_key
            response = clients[index].post(
                "/servers/add/",
                {
                    "name": f"Cloud {index}",
                    "address": "127.0.0.1",
                    "username": f"operator{index}",
                    "port": remote.port,
                },
            )
            self.assertEqual(response.status_code, 302)
            run_worker()
            attempts.append(DiscoveryAttempt.objects.latest("pk"))

        def confirm(index: int) -> int:
            close_old_connections()
            try:
                attempt = attempts[index]
                response = clients[index].post(
                    f"/servers/{attempt.server_id}/confirm-host/",
                    {
                        "attempt": attempt.pk,
                        "revision": 1,
                        "fingerprint": (first_key, second_key)[index].fingerprint,
                    },
                )
                return response.status_code
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(confirm, (0, 1)))
        self.assertCountEqual(outcomes, (302, 409))
        written = trust.read_text()
        self.assertEqual(sum(key.get_base64() in written for key in (first_key, second_key)), 1)
        self.assertEqual(remote.auth_attempts, 0)
