import re
import secrets
import tempfile
from pathlib import Path
from typing import ClassVar, override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.core.checks import run_checks
from django.test import Client, SimpleTestCase, TestCase, override_settings

from .vite import ManifestError, load_manifest, parse_manifest, production_tags

TEST_MANIFEST = Path(__file__).resolve().parent / "testdata" / "manifest.json"


@override_settings(VITE_MANIFEST_PATH=TEST_MANIFEST, VITE_DEV_SERVER_URL="")
class ViteEntryTests(SimpleTestCase):
    def test_production_tags_follow_vite_backend_order(self) -> None:
        html = production_tags(load_manifest(TEST_MANIFEST), "main.ts")
        self.assertEqual(
            html,
            '<link rel="stylesheet" href="/static/dist/assets/main-5UjPuW-k.css">'
            '<link rel="stylesheet" href="/static/dist/assets/shared-ChJ_j-JJ.css">'
            '<script type="module" src="/static/dist/assets/main-BRBmoGS9.js"></script>'
            '<link rel="modulepreload" href="/static/dist/assets/shared-B7PI925R.js">',
        )

    def test_classic_entries_render_blocking_scripts(self) -> None:
        manifest = load_manifest(TEST_MANIFEST)
        self.assertEqual(
            production_tags(manifest, "uswds-init.ts", classic=True),
            '<script src="/static/dist/assets/uswds-init-Dtdz5Z6j.js"></script>',
        )
        with self.assertRaisesMessage(ManifestError, "cannot import other chunks"):
            production_tags(manifest, "main.ts", classic=True)

    def test_pages_use_the_manifest_without_a_development_server(self) -> None:
        response = self.client.get("/accounts/login/")
        content = response.content.decode()
        # The USWDS initializer runs before first paint; the application module is deferred.
        self.assertLess(
            content.index('<script src="/static/dist/assets/uswds-init-Dtdz5Z6j.js"></script>'),
            content.index('<script type="module" src="/static/dist/assets/main-BRBmoGS9.js">'),
        )
        self.assertNotContains(response, "@vite/client")

    @override_settings(VITE_DEV_SERVER_URL="http://localhost:5173")
    def test_development_server_serves_modules(self) -> None:
        response = self.client.get("/accounts/login/")
        for entry in ("uswds-init.ts", "main.ts"):
            self.assertContains(
                response,
                '<script type="module" src="http://localhost:5173/@vite/client"></script>'
                f'<script type="module" src="http://localhost:5173/{entry}"></script>',
            )
        self.assertNotContains(response, "/static/dist/")

    def test_missing_manifest_explains_the_build_step(self) -> None:
        with self.assertRaisesMessage(ManifestError, "Run `npm run build`"):
            load_manifest(TEST_MANIFEST.with_name("missing.json"))

    def test_invalid_manifests_are_rejected(self) -> None:
        cases = {
            "not json": "{",
            "not an object": "[]",
            "missing file": '{"main.ts": {"isEntry": true}}',
            "absolute file": '{"main.ts": {"file": "/etc/passwd", "isEntry": true}}',
            "parent file": '{"main.ts": {"file": "../secret.js", "isEntry": true}}',
            "invalid css": '{"main.ts": {"file": "a.js", "css": "a.css"}}',
            "invalid imports": '{"main.ts": {"file": "a.js", "imports": [1]}}',
        }
        for label, text in cases.items():
            with self.subTest(label), self.assertRaises(ManifestError):
                parse_manifest(text)

    def test_unknown_or_non_entry_chunks_are_rejected(self) -> None:
        manifest = load_manifest(TEST_MANIFEST)
        for entry in ("missing.ts", "fonts/inter.woff2"):
            with self.subTest(entry), self.assertRaises(ManifestError):
                production_tags(manifest, entry)
        broken = parse_manifest('{"main.ts": {"file": "a.js", "isEntry": true, "imports": ["x"]}}')
        with self.assertRaisesMessage(ManifestError, "'x' is missing"):
            production_tags(broken, "main.ts")

    def test_manifest_changes_are_read_after_a_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text('{"main.ts": {"file": "a.js", "isEntry": true}}', encoding="utf-8")
            self.assertEqual(load_manifest(path)["main.ts"].file, "a.js")
            path.write_text('{"main.ts": {"file": "bb.js", "isEntry": true}}', encoding="utf-8")
            self.assertEqual(load_manifest(path)["main.ts"].file, "bb.js")


class DeploymentCheckTests(SimpleTestCase):
    def check_ids(self) -> list[str]:
        return [message.id or "" for message in run_checks(include_deployment_checks=True)]

    @override_settings(VITE_MANIFEST_PATH=TEST_MANIFEST, VITE_DEV_SERVER_URL="")
    def test_built_assets_pass(self) -> None:
        self.assertFalse([i for i in self.check_ids() if i.startswith("dashboard.")])

    @override_settings(VITE_MANIFEST_PATH=TEST_MANIFEST.with_name("missing.json"))
    def test_missing_build_fails(self) -> None:
        self.assertIn("dashboard.E002", self.check_ids())

    @override_settings(VITE_DEV_SERVER_URL="http://localhost:5173")
    def test_development_server_fails(self) -> None:
        self.assertIn("dashboard.E001", self.check_ids())


@override_settings(VITE_MANIFEST_PATH=TEST_MANIFEST, VITE_DEV_SERVER_URL="")
class SignInTests(TestCase):
    user: ClassVar[User]
    password = secrets.token_urlsafe(16)

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator", password=cls.password)

    def test_sign_in_page_uses_uswds_form_controls(self) -> None:
        response = self.client.get("/accounts/login/")
        self.assertContains(response, '<h1 id="sign-in-heading">Sign in to Barectl</h1>', html=True)
        self.assertContains(response, 'class="usa-input"', count=2)
        self.assertContains(response, 'autocomplete="current-password"')
        self.assertContains(response, "autofocus")
        self.assertNotContains(response, "Sign out")
        self.assertNotContains(response, "usa-menu-btn")

    def test_invalid_credentials_show_a_focused_error_summary(self) -> None:
        response = self.client.post(
            "/accounts/login/", {"username": "operator", "password": "wrong"}
        )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        summary = re.search(r'<div class="usa-alert usa-alert--error"[^>]*>', content)
        self.assertIsNotNone(summary)
        self.assertIn("autofocus", summary.group(0) if summary else "")
        self.assertIn("Please enter a correct username and password", content)
        # Only the summary requests focus after a failed attempt.
        self.assertEqual(content.count("autofocus"), 1)

    def test_missing_fields_are_described_by_their_errors(self) -> None:
        response = self.client.post("/accounts/login/", {"username": "", "password": ""})
        self.assertContains(response, 'id="id_username_error"')
        self.assertContains(response, 'aria-describedby="id_username_error"')
        self.assertContains(response, 'aria-invalid="true"', count=2)
        self.assertContains(response, 'href="#id_password"')

    def test_valid_credentials_return_to_the_requested_page(self) -> None:
        response = self.client.post(
            "/accounts/login/?next=/%3Fq%3Dweb",
            {"username": "operator", "password": self.password, "next": "/?q=web"},
        )
        self.assertRedirects(response, "/?q=web", fetch_redirect_response=False)

    def test_sign_in_requires_csrf(self) -> None:
        client = Client(enforce_csrf_checks=True)
        response = client.post("/accounts/login/", {"username": "operator", "password": "x"})
        self.assertEqual(response.status_code, 403)
