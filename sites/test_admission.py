"""Site admission against a simulated server, without the database or the worker."""

from typing import override
from unittest import mock

from django.test import SimpleTestCase

from bootstrap import inspection as bootstrap_inspection
from bootstrap import native as bootstrap_native
from bootstrap.fakes import PREPARATION_READ_ONLY, UbuntuServer
from bootstrap.models import Action, PlanEffect, PlanRefusal, Privilege
from bootstrap.review import review as bootstrap_review
from discovery.fakes import READ_ONLY, FakeServer

from . import admission, inspection, native
from .convention import Application, Stage, render_pool, render_site
from .fakes import Node, SiteServer, site_read_only

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
PROBE = "0123456789abcdef0123456789abcdef"
NAMES = ("shop.example.com", "www.shop.example.com")


class AdmissionTestCase(SimpleTestCase):
    @override
    def setUp(self) -> None:
        self.remote = FakeServer()
        self.server = SiteServer()
        self.addCleanup(self.assert_read_only)

    def assert_read_only(self) -> None:
        for command in self.remote.commands:
            self.assertTrue(
                READ_ONLY.fullmatch(command)
                or PREPARATION_READ_ONLY.fullmatch(command)
                or site_read_only(command),
                f"Not a read-only command: {command}",
            )

    def review(
        self, identifier: str = "shop", names: tuple[str, ...] = NAMES
    ) -> admission.SiteDraft:
        self.server.answer(self.remote)
        evidence = inspection.inspect(self.remote, identifier, PROBE)
        return admission.review(identifier, names, PROBE, evidence)

    def reasons(self, draft: admission.SiteDraft) -> list[str]:
        return [reason for reason, _ in draft.refusals]

    def refused(self, reason: str, fragment: str) -> admission.SiteDraft:
        draft = self.review()
        self.assertIn(reason, self.reasons(draft), draft.refusals)
        text = " ".join(text for found, text in draft.refusals if found == reason)
        self.assertIn(fragment, text)
        self.assertEqual(draft.files, [])
        return draft


class EligibleTests(AdmissionTestCase):
    def test_an_untrusted_installed_supply_refuses_site_changes(self) -> None:
        self.server.ubuntu.trusted = False
        draft = self.review()
        self.assertFalse(draft.eligible)
        self.assertEqual(draft.files, [])
        self.assertIn(Reason.INCOMPLETE, self.reasons(draft))
        self.assertIn("PHP supply", " ".join(text for _, text in draft.refusals))

    def test_finishing_a_selected_branch_creates_only_its_missing_pool(self) -> None:
        self.server.add_site("shop", NAMES, revision=4)
        self.server.pools.remove("shop")
        draft = self.review()
        self.assertEqual(draft.refusals, [])
        self.assertEqual(draft.revision, 4)
        self.assertIn("Finish", draft.intent)
        files = {item.role: item for item in draft.files}
        self.assertEqual(files["pool"].content, render_pool("shop", php_version="8.5"))
        self.assertIn(files["nginx_source"].path, draft.retained)

    def test_a_request_cannot_switch_a_selected_site_to_legacy_bytes(self) -> None:
        self.server.add_site("shop", NAMES, revision=4)
        self.server.answer(self.remote)
        evidence = inspection.inspect(
            self.remote, "shop", PROBE, php_version="8.5", convention_revision=3
        )
        draft = admission.review("shop", NAMES, PROBE, evidence)
        self.assertFalse(draft.eligible)
        self.assertIn(Reason.NOT_FOLLOWING, self.reasons(draft))
        self.assertEqual(draft.files, [])

    def test_a_conflicting_pool_on_another_branch_refuses_dependent_management(self) -> None:
        self.server.add_site("shop", NAMES, revision=4)
        self.server.files["/etc/php/8.4/fpm/pool.d/shop.conf"] = render_pool("shop")
        draft = self.review()
        self.assertIn(Reason.NOT_FOLLOWING, self.reasons(draft))
        self.assertIn("conflicting pools", " ".join(text for _, text in draft.refusals))
        self.assertEqual(draft.files, [])

    def test_a_stock_server_admits_the_site_with_every_effect(self) -> None:
        draft = self.review()
        self.assertEqual(draft.refusals, [])
        self.assertTrue(draft.ipv6)
        self.assertEqual(
            [kind for kind, _ in draft.effects],
            [
                Effect.SITE_ACCOUNT,
                Effect.SITE_DIRECTORIES,
                Effect.SITE_FILES,
                Effect.SERVICE_RELOAD,
                Effect.HTTP_ROUTING,
                Effect.ACCEPTANCE_PROBE,
                Effect.ISOLATION_LIMITS,
                Effect.NO_ROLLBACK,
            ],
        )
        files = {item.role: item for item in draft.files}
        self.assertEqual(files["nginx_source"].content, render_site("shop", NAMES, ipv6=True))
        self.assertEqual(files["probe"].path, f"/var/www/shop/public/probe-{PROBE}.php")
        self.assertTrue(files["probe"].temporary)
        self.assertEqual(
            [(d.path, d.owner, d.group, d.mode) for d in draft.directories],
            [
                ("/var/www/shop", "root", "root", "0755"),
                ("/var/www/shop/public", "sshop", "www-data", "0750"),
                ("/var/www/shop/private", "sshop", "sshop", "0700"),
            ],
        )
        account = draft.account
        if account is None:
            self.fail(draft.refusals)
        self.assertEqual(
            account.command,
            "/usr/sbin/useradd --user-group --no-create-home --home-dir /var/www/shop "
            "--shell /usr/sbin/nologin --no-log-init sshop",
        )
        self.assertEqual((account.predicted_uid, account.predicted_gid), (1003, 1003))
        self.assertLessEqual(draft.payload_bytes or 0, bootstrap_native.MAX_PAYLOAD - 2048)
        text = " ".join(text for _, text in draft.effects)
        self.assertIn("including the distribution's www pool and other sites", text)
        self.assertIn("No database catalog was read", text)

    def test_a_new_site_uses_the_releases_default_php(self) -> None:
        draft = self.review()
        self.assertEqual(draft.refusals, [])
        self.assertIn("/etc/php/8.5/fpm/pool.d/shop.conf", [f.path for f in draft.files])

    def test_root_reads_without_sudo(self) -> None:
        self.server.privilege = "root"
        draft = self.review()
        self.assertEqual(draft.refusals, [])
        platform = draft.platform
        if platform is None:
            self.fail(draft.refusals)
        self.assertEqual(platform.privilege, Privilege.ROOT)
        self.assertFalse(any(command.startswith("sudo") for command in self.remote.commands))

    def test_without_an_ipv6_listener_the_site_listens_on_ipv4_only(self) -> None:
        self.server.listeners = (("0.0.0.0", "nginx"),)  # noqa: S104
        draft = self.review()
        self.assertEqual(draft.refusals, [])
        self.assertFalse(draft.ipv6)
        self.assertNotIn("[::]", {f.role: f for f in draft.files}["nginx_source"].content)

    def test_another_convention_site_does_not_block_a_different_identifier(self) -> None:
        self.server.add_site("blog", ("blog.example.com",))
        self.server.sites["draft"] = (("draft.example.com",), False, False)
        draft = self.review()
        self.assertEqual(draft.refusals, [])

    def test_a_relative_enablement_link_is_recognized_as_discovery_does(self) -> None:
        self.server.add_site("blog", ("blog.example.com",))
        self.server.links["/etc/nginx/sites-enabled/blog.conf"] = "../sites-available/blog.conf"
        self.assertEqual(self.review().refusals, [])

    def test_a_fully_satisfied_request_is_a_no_op(self) -> None:
        self.server.add_site("shop", NAMES)
        draft = self.review()
        self.assertEqual(draft.refusals, [])
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.files, [])
        self.assertIn("not a claim that the site serves", draft.effects[0][1])

    def test_a_foreign_pool_file_is_tolerated_for_a_new_site(self) -> None:
        self.server.files["/etc/php/8.5/fpm/pool.d/custom.conf"] = "[custom]\n"
        self.assertEqual(self.review().refusals, [])

    def test_finishing_keeps_the_existing_account_ids_and_omits_its_effect(self) -> None:
        self.server.accounts["sshop"] = (1003, 1003)
        draft = self.review()
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertIn("Finish", draft.intent)
        self.assertIsNotNone(draft.account)
        if draft.account is None:
            self.fail("No reviewed account")
        self.assertEqual(draft.account.command, "")
        self.assertEqual((draft.account.predicted_uid, draft.account.predicted_gid), (1003, 1003))
        self.assertNotIn(Effect.SITE_ACCOUNT, [kind for kind, _ in draft.effects])

    def test_existing_application_content_is_outside_partial_admission(self) -> None:
        self.server.add_site("shop", NAMES)
        self.server.removed.add("/etc/nginx/sites-enabled/shop.conf")
        draft = self.review()
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertIn("/var/www/shop/public/index.html", draft.retained)
        self.assertNotIn(Effect.SITE_DIRECTORIES, [kind for kind, _ in draft.effects])


class RefusalTests(AdmissionTestCase):
    def test_narrowed_sudo_refuses_for_privilege_before_reading_configuration(self) -> None:
        self.server.privilege = "narrow"
        draft = self.refused(Reason.PRIVILEGE, "explicit authority")
        read = [c for c in self.remote.commands if c.startswith("sudo -n /usr/bin/")]
        self.assertEqual(read, [])
        self.assertEqual({item.kind for item in draft.evidence}, {"platform", "privilege"})

    def test_no_privilege_refuses(self) -> None:
        self.server.privilege = "none"
        self.refused(Reason.PRIVILEGE, "sudo")

    def test_a_name_of_another_site_collides(self) -> None:
        self.server.add_site("blog", ("blog.example.com", "www.shop.example.com"))
        self.refused(
            Reason.NOT_FOLLOWING,
            "The site blog already declares www.shop.example.com "
            "(/etc/nginx/sites-available/blog.conf)",
        )

    def test_a_foreign_literal_name_collides_case_insensitively(self) -> None:
        self.server.files["/etc/nginx/sites-available/legacy"] = (
            "server { listen 80; server_name SHOP.EXAMPLE.COM; }\n"
        )
        self.server.links["/etc/nginx/sites-enabled/legacy"] = "../sites-available/legacy"
        self.refused(Reason.NOT_FOLLOWING, "/etc/nginx/sites-enabled/legacy")

    def test_a_foreign_enabled_file_declaring_a_name_collides(self) -> None:
        self.server.files["/etc/nginx/sites-available/legacy"] = (
            "server {\n  listen 80;\n  server_name shop.example.com;\n}\n"
        )
        self.server.links["/etc/nginx/sites-enabled/legacy"] = "../sites-available/legacy"
        self.refused(
            Reason.NOT_FOLLOWING,
            "/etc/nginx/sites-enabled/legacy already declares shop.example.com",
        )

    def test_existing_certificate_paths_collide(self) -> None:
        self.server.paths["/etc/letsencrypt/live/shop"] = Node("d", 0o700, 0, 0, "root", "root")
        self.refused(Reason.COLLISION, "/etc/letsencrypt/live/shop")

    def test_another_site_on_the_server_is_tolerated(self) -> None:
        self.server.files["/etc/nginx/sites-available/private"] = "server {\n  listen 81;\n}\n"
        self.server.links["/etc/nginx/sites-enabled/private"] = "../sites-available/private"
        draft = self.review()
        self.assertEqual(draft.refusals, [])
        self.assertNotIn("listen 81", repr(draft.refusals) + repr(draft.evidence))

    def test_a_changed_convention_file_is_tolerated(self) -> None:
        text = render_site("blog", ("blog.example.com",), ipv6=True).replace("\t", "  ")
        self.server.files["/etc/nginx/sites-available/blog.conf"] = text
        self.server.links["/etc/nginx/sites-enabled/blog.conf"] = "../sites-available/blog.conf"
        self.assertEqual(self.review().refusals, [])

    def test_a_site_file_without_the_conf_suffix_is_tolerated(self) -> None:
        text = render_site("blog", ("blog.example.com",), ipv6=True)
        self.server.files["/etc/nginx/sites-available/blog"] = text
        self.server.links["/etc/nginx/sites-enabled/blog"] = "../sites-available/blog"
        self.assertEqual(self.review().refusals, [])

    def test_an_entry_on_another_filesystem_is_unsupported(self) -> None:
        self.server.mounts.add("/etc/nginx/conf.d")
        self.refused(Reason.UNSUPPORTED_LAYOUT, "/etc/nginx/conf.d (on another filesystem")

    def test_the_database_drivers_modules_are_the_distribution_s(self) -> None:
        # docs/v0.3-qualification.md#site-database-observations: ucf registers the drivers'
        # module files, and phpenmod links them from each SAPI's conf.d.
        self.server.drivers = ("mysql", "pgsql")
        draft = self.review()
        self.assertEqual(draft.refusals, [])

    def test_a_link_to_a_missing_module_file_is_unsupported(self) -> None:
        php = "/etc/php/8.5"
        self.server.links[f"{php}/fpm/conf.d/20-mysqli.ini"] = f"{php}/mods-available/mysqli.ini"
        self.refused(
            Reason.UNSUPPORTED_LAYOUT,
            f"{php}/fpm/conf.d/20-mysqli.ini (a link to no distribution module file)",
        )

    def test_a_link_to_a_module_file_of_the_administrator_is_unsupported(self) -> None:
        php = "/etc/php/8.5"
        self.server.files[f"{php}/mods-available/custom.ini"] = "extension=custom\n"
        self.server.links[f"{php}/fpm/conf.d/30-custom.ini"] = f"{php}/mods-available/custom.ini"
        self.refused(
            Reason.UNSUPPORTED_LAYOUT,
            f"{php}/fpm/conf.d/30-custom.ini (a link to no distribution module file)",
        )

    def test_a_conf_d_entry_is_unsupported(self) -> None:
        self.server.files["/etc/nginx/conf.d/cache.conf"] = "proxy_cache_path /tmp;\n"
        self.refused(Reason.UNSUPPORTED_LAYOUT, "/etc/nginx/conf.d/cache.conf")

    def test_a_modified_distribution_file_is_unsupported(self) -> None:
        self.server.changed.add("/etc/nginx/nginx.conf")
        self.refused(Reason.UNSUPPORTED_LAYOUT, "/etc/nginx/nginx.conf (changed")

    def test_a_missing_distribution_file_is_unsupported(self) -> None:
        self.server.removed.add("/etc/nginx/mime.types")
        self.refused(Reason.UNSUPPORTED_LAYOUT, "/etc/nginx/mime.types (a distribution default")

    def test_a_writable_convention_file_is_not_recognized(self) -> None:
        self.server.sites["blog"] = (("blog.example.com",), True, False)
        path = "/etc/nginx/sites-available/blog.conf"
        self.server.paths[path] = Node("f", 0o666, 0, 0, "root", "root")
        self.assertEqual(self.review().refusals, [])

    def test_another_php_release_is_unsupported(self) -> None:
        self.server.ubuntu.php_releases = (("php8.2-fpm", "8.2.10", "ii"),)
        self.refused(Reason.UNSUPPORTED_VERSION, "php8.2-fpm")

    def test_units_must_be_the_running_distribution_units(self) -> None:
        self.server.ubuntu.unit_drop_ins = "/etc/systemd/system/nginx.service.d/limits.conf"
        self.refused(Reason.SERVICE_UNIT, "drop-in")
        self.server = SiteServer()
        self.remote = FakeServer()
        self.server.ubuntu.php_active = "inactive"
        self.refused(Reason.SERVICE_UNIT, "php8.5-fpm.service is inactive/dead")

    def test_another_listener_on_port_80_is_refused(self) -> None:
        self.server.listeners = (("0.0.0.0", "nginx"), ("[::]", "apache2"))  # noqa: S104
        self.refused(Reason.LISTENER, "[::]")

    def test_remote_account_databases_are_unsupported(self) -> None:
        self.server.nsswitch = "passwd:         files sss\ngroup:          files sss\n"
        self.refused(Reason.UNSUPPORTED_LAYOUT, "files sss")

    def test_useradd_defaults_beyond_the_flags_are_named(self) -> None:
        self.server.useradd = "SHELL=/bin/sh\nGROUPS=sudo\nINACTIVE=30\n"
        self.refused(Reason.UNSUPPORTED_LAYOUT, "GROUPS, INACTIVE")

    def test_the_probe_needs_the_posix_extension(self) -> None:
        self.server.removed.add("/etc/php/8.5/fpm/conf.d/20-posix.ini")
        self.refused(Reason.PREREQUISITE, "posix")

    def test_the_default_site_must_stay_enabled(self) -> None:
        self.server.removed.add("/etc/nginx/sites-enabled/default")
        self.refused(Reason.PREREQUISITE, "default site is not enabled")

    def test_unsafe_ancestors_are_refused(self) -> None:
        self.server.paths["/var/www"] = Node("d", 0o777, 0, 0, "root", "root")
        self.refused(Reason.UNSUPPORTED_LAYOUT, "/var/www must be a directory owned by root")

    def no_removal_commands(self, draft: admission.SiteDraft) -> None:
        text = " ".join(text for _, text in draft.refusals)
        for command in ("userdel", "rm ", "rmdir", "systemctl"):
            self.assertNotIn(command, text)

    def test_an_exact_partial_site_is_finished_with_only_missing_effects(self) -> None:
        self.server.sites["shop"] = (NAMES, True, False)
        draft = self.review()
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertIn("Finish", draft.intent)
        self.assertIn("/etc/nginx/sites-available/shop.conf", draft.retained)
        self.assertNotIn("/etc/nginx/sites-enabled/shop.conf", draft.retained)
        self.assertIn("only the absent", " ".join(text for _, text in draft.effects))

    def test_a_wordpress_site_is_never_finished_into_another_form(self) -> None:
        for application in (Application.WORDPRESS, Application.WORDPRESS_GATE):
            with self.subTest(application=application):
                self.server.add_site("shop", NAMES)
                self.server.add_activated("shop", Stage.REDIRECT, application)
                self.server.pools.discard("shop")
                draft = self.review()
                self.assertFalse(draft.eligible)
                self.assertEqual(draft.files, [])
                self.assertIn(Reason.PREREQUISITE, self.reasons(draft))
                text = " ".join(text for _, text in draft.refusals)
                self.assertIn("challenge or HTTPS configuration", text)

    def test_a_foreign_resource_at_a_derived_name_is_refused(self) -> None:
        self.server.paths["/var/www/shop"] = Node("d", 0o755, 1001, 1001, "deploy", "deploy")
        draft = self.refused(Reason.NOT_FOLLOWING, "/var/www/shop")
        self.assertNotIn(Reason.COLLISION, self.reasons(draft))
        self.no_removal_commands(draft)

    def test_an_unlocked_account_at_the_derived_name_is_refused(self) -> None:
        self.server.accounts["sshop"] = (1003, 1003)
        self.server.locked = False
        draft = self.refused(Reason.NOT_FOLLOWING, "user sshop")
        self.no_removal_commands(draft)

    def test_changing_an_existing_sites_names_is_refused(self) -> None:
        self.server.add_site("shop", ("shop.example.com",))
        draft = self.refused(Reason.NOT_FOLLOWING, "/etc/nginx/sites-available/shop.conf")
        self.no_removal_commands(draft)

    def test_a_truncated_read_is_incomplete_evidence(self) -> None:
        self.server.truncated.add(
            bootstrap_native.privileged(native.tree_listing("8.5", all_branches=True), root=False)
        )
        self.refused(Reason.INCOMPLETE, "larger than Barectl reads")

    def test_a_change_while_reading_is_incomplete_evidence(self) -> None:
        self.server.changing = True
        self.refused(Reason.INCOMPLETE, "changed while Barectl read")

    def test_an_oversized_payload_is_refused_before_submission(self) -> None:
        with mock.patch.object(bootstrap_native, "MAX_PAYLOAD", 4096):
            draft = self.review()
        self.assertIn(Reason.PAYLOAD_TOO_LARGE, self.reasons(draft))
        self.assertEqual(draft.effects, [])


class StockProfileTests(SimpleTestCase):
    """Bootstrap's own profiles keep refusing a tree that holds site files."""

    def test_the_nginx_and_php_profiles_refuse_convention_files(self) -> None:
        for action, path in (
            (Action.NGINX, "/etc/nginx/sites-available/shop.conf"),
            (Action.PHP, "/etc/php/8.5/fpm/pool.d/shop.conf"),
        ):
            remote = FakeServer()
            ubuntu = UbuntuServer(nginx="installed", php="installed")
            ubuntu.extra_files[path] = "1" * 32
            ubuntu.answer(remote)
            evidence = bootstrap_inspection.inspect(remote, action)
            draft = bootstrap_review(action, evidence)
            refusals = [text for reason, text in draft.refusals if reason == Reason.CUSTOMIZED]
            self.assertTrue(any(path in text for text in refusals), draft.refusals)

    def test_the_php_profile_keeps_its_rules_with_database_drivers(self) -> None:
        for sites in (False, True):
            with self.subTest(sites=sites):
                remote = FakeServer()
                ubuntu = UbuntuServer(nginx="installed", php="installed")
                ubuntu.php_drivers = ("mysql", "pgsql")
                if sites:
                    ubuntu.extra_files["/etc/php/8.5/fpm/pool.d/shop.conf"] = "1" * 32
                ubuntu.answer(remote)
                draft = bootstrap_review(
                    Action.PHP, bootstrap_inspection.inspect(remote, Action.PHP)
                )
                reasons = [reason for reason, _ in draft.refusals]
                self.assertEqual(reasons, [Reason.CUSTOMIZED] if sites else [], draft.refusals)
                self.assertEqual(draft.transitions, [])
