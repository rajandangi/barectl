"""The normal creation form and browser-only WordPress first access."""

import base64
import hashlib
import tempfile
from typing import override
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import Route, expect

from bootstrap.models import PhpRuntimeSnapshot
from dashboard.browser_testing import BrowserTestCase
from discovery.models import DiscoverySnapshot
from servers.models import Server

KEYS = """async () => {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open('barectl-first-access', 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const result = await new Promise(resolve => {
    const request = db.transaction('keys').objectStore('keys').getAll();
    request.onsuccess = () => resolve(request.result.map(key => ({
      extractable: key.privateKey.extractable, user: key.user, expires: key.expires
    })));
  });
  db.close();
  return result;
}"""


@tag("browser")
class CreationBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    @override
    def setUp(self) -> None:
        super().setUp()
        self.user.user_permissions.add(Permission.objects.get(codename="view_siteobservation"))
        self.server = Server.objects.get(name="Production")
        self.record_installed_php()
        snapshot = DiscoverySnapshot.objects.filter(attempt__server=self.server).latest("pk")
        snapshot.arch_value = "aarch64"
        snapshot.save(update_fields=("arch_value",))
        PhpRuntimeSnapshot.objects.create(snapshot=snapshot, supply="ubuntu", default_branch="8.3")
        self.sign_in()

    def creation(self) -> None:
        self.page.goto(
            f"{self.live_server_url}/servers/{self.server.pk}/sites/new/?application=wordpress"
        )
        expect(self.page.get_by_role("heading", name="Create WordPress site")).to_be_visible()
        self.page.get_by_label("Domain", exact=True).fill("shop.example.com")
        self.page.get_by_label("Site title").fill("Shop")
        self.page.get_by_label("Administrator email").fill("owner@example.com")
        self.page.get_by_label("Accept the certificate authority agreement").check()

    def capture_key(self) -> str:
        def hold(route: Route) -> None:
            if route.request.method == "POST":
                route.fulfill(status=204)
            else:
                route.continue_()

        self.page.route("**/sites/new/", hold)
        with self.page.expect_request(
            lambda request: request.method == "POST" and request.url.endswith("/sites/new/")
        ) as submitted:
            self.page.get_by_role("button", name="Create WordPress site").click()
        values = parse_qs(submitted.value.post_data or "")
        self.assertEqual(values["application"], ["wordpress"])
        self.assertEqual(values["domain"], ["shop.example.com"])
        return values["first_access_spki"][0]

    def reveal_form(self, digest: str) -> None:
        self.page.evaluate(
            """({digest, user}) => {
              const form = document.createElement('form');
              form.method = 'post'; form.action = '/test-first-access/';
              form.dataset.firstAccessReveal = '';
              form.dataset.firstAccessDigest = digest; form.dataset.firstAccessUser = user;
              form.innerHTML = '<button type="submit">Show administrator password</button>' +
                '<output data-first-access-password hidden></output>' +
                '<p role="status" data-first-access-status></p>';
              document.querySelector('main').append(form);
            }""",
            {"digest": digest, "user": str(self.user.pk)},
        )

    def test_one_form_retains_a_nonexportable_key_across_reload_and_decrypts_only_in_browser(
        self,
    ) -> None:
        self.creation()
        key = self.capture_key()
        stored = self.page.evaluate(KEYS)
        self.assertEqual(len(stored), 1)
        self.assertFalse(stored[0]["extractable"])
        self.assertEqual(stored[0]["user"], str(self.user.pk))
        self.page.reload()
        self.assertEqual(self.page.evaluate(KEYS), stored)
        public = serialization.load_der_public_key(base64.b64decode(key, validate=True))
        self.assertIsInstance(public, rsa.RSAPublicKey)
        if not isinstance(public, rsa.RSAPublicKey):
            self.fail("The browser did not produce an RSA public key.")
        password = "A1" * 16
        ciphertext = public.encrypt(
            password.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        digest = hashlib.sha256(base64.b64decode(key)).hexdigest()
        self.page.route(
            "**/test-first-access/",
            lambda route: route.fulfill(
                json={"ciphertext": base64.b64encode(ciphertext).decode(), "key_sha256": digest}
            ),
        )
        self.reveal_form(digest)
        self.page.get_by_role("button", name="Show administrator password").click()
        expect(self.page.locator("[data-first-access-password]")).to_have_text(password)
        self.assertEqual(self.page.evaluate(KEYS), [])
        self.assertFalse(any(password in (request.post_data or "") for request in self.requests))
        expect(self.page.get_by_role("button", name="Show administrator password")).to_be_disabled()
        self.page.set_viewport_size({"width": 320, "height": 800})
        self.assertEqual(
            self.page.evaluate(
                "Math.max(0, document.documentElement.scrollWidth - "
                "document.documentElement.clientWidth)"
            ),
            0,
        )

    def test_missing_browser_key_preserves_delivery_and_names_explicit_recovery(self) -> None:
        self.creation()
        self.reveal_form("a" * 64)
        self.page.get_by_role("button", name="Show administrator password").click()
        expect(self.page.locator("[data-first-access-reveal] [role=status]")).to_contain_text(
            "Reset administrator password"
        )
        self.assertFalse(
            any(request.url.endswith("/test-first-access/") for request in self.requests)
        )

    def test_expired_key_is_removed_without_consuming_delivery(self) -> None:
        self.creation()
        key = self.capture_key()
        self.page.evaluate(
            """async () => {
              const db = await new Promise(resolve => {
                const request = indexedDB.open('barectl-first-access', 1);
                request.onsuccess = () => resolve(request.result);
              });
              await new Promise(resolve => {
                const transaction = db.transaction('keys', 'readwrite');
                const store = transaction.objectStore('keys');
                const request = store.openCursor();
                request.onsuccess = () => {
                  const cursor = request.result;
                  if (cursor) {
                    cursor.update({...cursor.value, expires: Date.now() - 1000});
                    cursor.continue();
                  }
                };
                transaction.oncomplete = () => resolve();
              });
              db.close();
            }"""
        )
        self.reveal_form(hashlib.sha256(base64.b64decode(key)).hexdigest())
        self.page.get_by_role("button", name="Show administrator password").click()
        expect(self.page.locator("[data-first-access-reveal] [role=status]")).to_contain_text(
            "expired"
        )
        self.assertEqual(self.page.evaluate(KEYS), [])
        self.assertFalse(
            any(request.url.endswith("/test-first-access/") for request in self.requests)
        )

    def test_logout_clears_the_retained_key_before_navigation(self) -> None:
        self.creation()
        self.capture_key()
        self.assertEqual(len(self.page.evaluate(KEYS)), 1)
        self.page.get_by_role("button", name="Sign out").click()
        expect(
            self.page.get_by_role("heading", name="Sign in to Barectl", exact=True)
        ).to_be_visible()
        self.assertEqual(self.page.evaluate(KEYS), [])
