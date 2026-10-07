"""The challenge route plan workflow: request, worker, plan, review and permissions.

Real views, services, the lifecycle, the worker, persistence and rendering run; only remote
execution is substituted, with ``SiteServer`` answering at ``discovery.ssh.connect``.
"""

from bootstrap.models import (
    Action,
    ConfigurationPlan,
    PlanEffect,
    PlanPreparation,
    PlanRefusal,
)
from sites.convention import Stage, render_site
from sites.fakes import SITE_PERMISSIONS, Node
from sites.services import request_site_preparation

from .fakes import NAMES, TLS_PERMISSIONS, TlsTestCase
from .models import PlanChallenge, TlsRequest

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind


class ChallengePreparationTests(TlsTestCase):
    def latest_plan(self) -> ConfigurationPlan:
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        found = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if found is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return found

    def refusals(self, plan: ConfigurationPlan) -> dict[str, str]:
        return dict(plan.refusals.values_list("reason", "text"))

    def test_a_complete_site_gets_a_reviewed_route_without_writing(self) -> None:
        self.site.add_site("shop", NAMES)
        response = self.prepare_challenge()
        self.assertRedirects(response, f"/servers/{self.server.pk}/advanced/#tls-plans")
        self.assertEqual(TlsRequest.objects.get().identifier, "shop")
        plan = self.latest_plan()
        self.assertEqual(self.refusals(plan), {})
        self.assertEqual(
            (plan.action, plan.eligible, plan.no_changes), (Action.TLS_CHALLENGE, True, False)
        )
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [
                Effect.CHALLENGE_ROUTE,
                Effect.PREIMAGE_BACKUP,
                Effect.SERVICE_RELOAD,
                Effect.ACCEPTANCE_PROBE,
                Effect.NO_ROLLBACK,
            ],
        )
        challenge = PlanChallenge.objects.get(plan=plan)
        self.assertEqual(challenge.preimage, render_site("shop", NAMES, ipv6=True))
        self.assertEqual(
            challenge.content, render_site("shop", NAMES, ipv6=True, stage=Stage.CHALLENGE)
        )
        self.assertEqual((challenge.creates_letsencrypt, challenge.creates_backups), (True, True))
        self.assertLess(challenge.payload_bytes or 0, 16 * 1024)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "location ^~ /.well-known/acme-challenge/")
        self.assertContains(page, "/var/backups/nginx/shop.conf.&lt;unit&gt;")
        self.assertNotContains(page, "Apply plan")
        self.assert_read_only()

    def test_the_route_is_offered_to_appliers_only(self) -> None:
        self.site.add_site("shop", NAMES)
        self.prepare_challenge(perms=(*TLS_PERMISSIONS, "apply_tlsplan"))
        plan = self.latest_plan()
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, f"Apply plan {plan.pk}, Site challenge route, revision 3")

    def test_a_site_already_serving_challenges_has_no_changes(self) -> None:
        self.site.add_site("shop", NAMES)
        self.site.add_challenge("shop")
        self.prepare_challenge()
        plan = self.latest_plan()
        self.assertEqual(self.refusals(plan), {})
        self.assertTrue(plan.no_changes)
        self.assertFalse(PlanChallenge.objects.exists())

    def test_there_must_be_a_complete_site(self) -> None:
        self.prepare_challenge()
        self.assertIn(Reason.NOT_FOLLOWING, self.refusals(self.latest_plan()))
        self.site.add_site("shop", NAMES, complete=False)
        self.prepare_challenge()
        self.assertIn(Reason.NOT_FOLLOWING, self.refusals(self.latest_plan()))

    def test_an_existing_lineage_does_not_block_a_satisfied_challenge_route(self) -> None:
        self.site.add_site("shop", NAMES)
        self.site.add_challenge("shop")
        self.site.paths["/etc/letsencrypt/live/shop"] = Node("d", 0o700, 0, 0, "root", "root")
        for stage in (Stage.CHALLENGE, Stage.HTTPS):
            with self.subTest(stage=stage):
                self.site.stages["shop"] = stage
                self.prepare_challenge()
                plan = self.latest_plan()
                self.assertTrue(plan.eligible and plan.no_changes, self.refusals(plan))
        self.assert_read_only()

    def test_a_new_challenge_route_still_refuses_a_reserved_lineage(self) -> None:
        self.site.add_site("shop", NAMES)
        self.site.paths["/etc/letsencrypt/live/shop"] = Node("d", 0o700, 0, 0, "root", "root")
        self.prepare_challenge()
        self.assertIn(Reason.COLLISION, self.refusals(self.latest_plan()))

    def test_unsafe_or_foreign_directories_are_refused(self) -> None:
        self.site.add_site("shop", NAMES)
        cases = {
            "/var/lib/letsencrypt": Node("d", 0o777, 0, 0, "root", "root"),
            "/var/backups/nginx": Node("d", 0o755, 0, 0, "root", "root"),
            "/var/lib/letsencrypt/shop": Node("d", 0o750, 0, 33, "root", "www-data"),
        }
        for path, node in cases.items():
            with self.subTest(path=path):
                self.site.paths[path] = node
                self.prepare_challenge()
                plan = self.latest_plan()
                self.assertFalse(plan.eligible)
                self.assertIn(path, " ".join(self.refusals(plan).values()))
                del self.site.paths[path]

    def test_site_plans_stay_available_beside_a_route(self) -> None:
        self.site.add_site("shop", NAMES)
        self.site.add_challenge("shop")
        # The same site is satisfied, and another one can still be created.
        self.sign_in_with(*SITE_PERMISSIONS)
        self.site.answer(self.remote)
        request_site_preparation(self.server, self.user, "shop", NAMES)
        self.run_worker()
        plan = self.latest_plan()
        self.assertTrue(plan.no_changes, self.refusals(plan))
        self.assertIn("HTTP-01 challenge route", plan.effects.get().text)
        self.prepare_site("blog", "blog.example.com", perms=SITE_PERMISSIONS)
        plan = self.latest_plan()
        self.assertTrue(plan.eligible and not plan.no_changes, self.refusals(plan))

    def test_permissions_are_separate_from_sites_and_bootstrap(self) -> None:
        self.site.add_site("shop", NAMES)
        self.sign_in_with(*SITE_PERMISSIONS, "view_configurationplan", "prepare_configurationplan")
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/challenge/prepare/", {"identifier": "shop"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertNotContains(self.client.get(f"/servers/{self.server.pk}/advanced/"), "TLS plans")
        self.assertFalse(TlsRequest.objects.exists())

    def test_an_invalid_identifier_is_refused_by_the_form(self) -> None:
        self.sign_in_with(*TLS_PERMISSIONS)
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/challenge/prepare/", {"identifier": "Shop!"}
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/advanced/#tls-plans")
        self.assertFalse(TlsRequest.objects.exists())
