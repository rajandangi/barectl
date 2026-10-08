"""Passive WordPress application evidence (docs/wordpress.md#passive-application-discovery).

Observation rules run through ``collect`` on a simulated server. The fixed file inspection
is the real server-side script, run against a temporary copy of the simulated files.
"""

import re
from typing import override

from sites.convention import Application, Stage
from wordpress.convention import CORE_VERSION
from wordpress.fakes import SALT_VALUES, ApplicationServer

from . import ssh
from .fakes import (
    ObservationTestCase,
    SitePoolFixtures,
    add_site,
    mariadb_rows,
    postgresql_rows,
)
from .models import (
    ApplicationState,
    ConfigurationState,
    CoreQualification,
    LoaderState,
    SchemaState,
    SiteRouting,
)
from .snapshot import ObservedApplication, ObservedSite

HOSTILE = re.compile(r"(?:^|[\s;|&])(?:php[0-9.]*|wp|sudo)\s|wp-cli|\.phar")


class ApplicationObservationTests(SitePoolFixtures, ObservationTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        add_site(self.remote, "shop", ("shop.test", "www.shop.test"))
        add_site(self.remote, "blog", ("blog.test",))
        self.apps = ApplicationServer(self.remote)
        self.remote.catalogs.mariadb["sshop"] = mariadb_rows("sshop")

    def sites(self) -> dict[str, ObservedSite]:
        return {site.identifier: site for site in self.collect().sites.value}

    def application(self, identifier: str = "shop") -> ObservedApplication:
        application = self.sites()[identifier].application
        if application is None:
            self.fail("No application evidence was observed.")
        return application

    def assert_no_application_code_ran(self) -> None:
        offending = [c for c in self.remote.commands if HOSTILE.search(c.split("'")[0])]
        self.assertEqual(offending, [])

    def test_ordinary_discovery_reads_no_private_evidence_and_never_escalates(self) -> None:
        self.apps.install()
        application = self.application()
        self.assertEqual(application.state, ApplicationState.UNREADABLE)
        self.assertIn("never escalates", " ".join(application.limits))
        self.assertEqual(application.configuration_digest, "")
        self.assertEqual(self.apps.inspections, [])
        self.assertFalse([c for c in self.remote.commands if c.startswith("mariadb")])
        self.assert_no_application_code_ran()

    def test_root_finds_no_application_on_a_site_that_has_none(self) -> None:
        self.apps.as_root()
        for identifier in ("shop", "blog"):
            application = self.application(identifier)
            self.assertEqual(application.state, ApplicationState.ABSENT)
            self.assertEqual(application.limits, ())
        self.assertEqual(self.apps.inspections, [])

    def test_a_matching_administrator_created_application_is_installed(self) -> None:
        self.apps.as_root()
        self.apps.install()
        application = self.application()
        self.assertEqual(application.state, ApplicationState.INSTALLED)
        self.assertEqual(application.core_version, CORE_VERSION)
        self.assertEqual(application.qualification, CoreQualification.QUALIFIED)
        self.assertEqual(
            (application.loader, application.configuration, application.schema),
            (LoaderState.EXACT, ConfigurationState.SUPPORTED, SchemaState.COMPLETE),
        )
        self.assertEqual(len(application.configuration_digest), 64)
        self.assertEqual((application.markers_present, application.markers_total), (7, 7))
        self.assertEqual(application.site_url, "https://shop.test")
        self.assertEqual((application.blocked, application.limits), ((), ()))
        self.assert_no_application_code_ran()

    def test_no_secret_leaves_the_server(self) -> None:
        self.apps.as_root()
        self.apps.install()
        self.collect()
        text = repr(self.collected)
        for salt in SALT_VALUES:
            self.assertNotIn(salt, text)
        self.assertNotIn("DB_PASSWORD", text)
        for command in self.remote.commands:
            self.assertNotIn("wp_users`", command)
            self.assertNotIn("FROM `", command.replace("FROM `sshop`.`wp_options`", ""))

    def test_files_alone_are_a_candidate(self) -> None:
        self.apps.as_root()
        self.apps.install(loader="", configuration="", tables="none")
        application = self.application()
        self.assertEqual(application.state, ApplicationState.CANDIDATE)
        self.assertEqual(application.schema, SchemaState.ABSENT)

    def test_incomplete_evidence_is_partial_not_installed(self) -> None:
        self.apps.as_root()
        cases = {
            "no tables": {"tables": "none"},
            "some core tables": {"tables": "partial"},
            "no release files": {"core": False},
            "no private configuration": {"configuration": ""},
            "no loader": {"loader": ""},
        }
        for label, options in cases.items():
            with self.subTest(label):
                self.apps.install(**options)  # type: ignore[arg-type]
                self.assertEqual(self.application().state, ApplicationState.PARTIAL, label)

    def test_tables_without_any_file_are_partial(self) -> None:
        self.apps.as_root()
        self.apps.install(core=False, loader="", configuration="")
        self.assertEqual(self.application().state, ApplicationState.PARTIAL)

    def test_the_routing_form_alone_is_partial(self) -> None:
        self.apps.as_root()
        self.activate(Application.WORDPRESS_GATE)
        site = self.sites()["shop"]
        self.assertEqual(site.routing, SiteRouting.WORDPRESS_GATE)
        self.assertEqual(site.application and site.application.state, ApplicationState.PARTIAL)

    def activate(self, application: Application, canonical: str = "") -> None:
        self.activate_site(
            "shop",
            ("shop.test", "www.shop.test"),
            stage=Stage.REDIRECT,
            application=application,
            canonical=canonical,
        )

    def test_edited_or_hostile_resources_block_dependent_actions(self) -> None:
        self.apps.as_root()
        cases = {
            "an edited loader": {"loader": "<?php\nsystem('x');\n"},
            "a standard configuration": {"configuration": "<?php\ndefine( 'DB_PASSWORD', 'x' );\n"},
            "altered core columns": {"tables": "altered"},
            "an ambiguous prefix": {"ambiguous": True},
            "another site": {"url": "https://other.example"},
            "a path": {"url": "https://shop.test/blog"},
            "plain http": {"url": "http://shop.test"},
        }
        for label, options in cases.items():
            with self.subTest(label):
                self.apps.install(**options)  # type: ignore[arg-type]
                application = self.application()
                self.assertEqual(application.state, ApplicationState.BLOCKED, label)
                self.assertTrue(application.blocked)
                self.assertNotIn("system", " ".join(application.blocked))
        self.assert_no_application_code_ran()

    def test_the_canonical_name_of_the_site_file_must_match_the_options(self) -> None:
        self.apps.as_root()
        self.activate(Application.WORDPRESS, "www.shop.test")
        self.apps.install(url="https://shop.test")
        self.assertEqual(self.application().state, ApplicationState.BLOCKED)
        self.apps.install(url="https://www.shop.test")
        self.assertEqual(self.application().state, ApplicationState.INSTALLED)
        self.assertEqual(self.sites()["shop"].canonical_name, "www.shop.test")

    def test_an_externally_updated_core_is_reported_not_downgraded(self) -> None:
        self.apps.as_root()
        for version, qualification in (
            ("8.0.1", CoreQualification.NEWER),
            ("6.9.4", CoreQualification.OLDER),
        ):
            self.apps.install(version=version)
            application = self.application()
            self.assertEqual(application.state, ApplicationState.INSTALLED)
            self.assertEqual(application.qualification, qualification)
            self.assertIn(version, application.warning)
            self.assertIn(CORE_VERSION, application.warning)

    def test_unread_catalogs_are_evidence_limits_never_absence_or_proof(self) -> None:
        self.apps.as_root()
        self.apps.install()
        self.apps.failing.add("schema")
        failed = self.application()
        self.assertEqual(failed.state, ApplicationState.UNREADABLE)
        self.assertEqual(failed.schema, SchemaState.NOT_READ)
        self.assertTrue(failed.limits)
        self.apps.failing.clear()
        self.apps.failing.add("options")
        self.assertEqual(self.application().state, ApplicationState.UNREADABLE)

    def test_a_stopped_database_is_never_read_around(self) -> None:
        self.apps.as_root()
        self.apps.install()
        self.assertEqual(self.application().state, ApplicationState.INSTALLED)
        self.apps.failing.add("schema")
        # The earlier successful collection is not a fallback.
        self.assertEqual(self.application().state, ApplicationState.UNREADABLE)

    def test_unreadable_files_are_not_absent(self) -> None:
        self.apps.as_root()
        self.apps.install()
        self.remote.unreadable.add("/var/www/shop/private")
        self.assertEqual(self.application().state, ApplicationState.UNREADABLE)

    def test_a_postgresql_binding_blocks_a_wordpress_tree(self) -> None:
        self.apps.as_root()
        self.remote.catalogs.mariadb.pop("sshop")
        self.remote.catalogs.postgresql["sshop"] = postgresql_rows("sshop")
        self.apps.install()
        application = self.application()
        self.assertEqual(application.state, ApplicationState.BLOCKED)
        self.assertIn("PostgreSQL", " ".join(application.blocked))

    def test_application_evidence_does_not_change_the_site_infrastructure_state(self) -> None:
        self.apps.as_root()
        before = self.sites()["shop"]
        self.apps.install(loader="<?php\nevil();\n", tables="altered")
        after = self.sites()["shop"]
        self.assertEqual(after.state, before.state)
        self.assertEqual(after.outcome, before.outcome)
        self.assertEqual(after.missing, before.missing)

    def test_a_missing_ssh_identity_read_leaves_application_evidence_unreadable(self) -> None:
        self.remote.results["id -u"] = ssh.CommandResult(1, "")
        self.apps.install()
        self.assertEqual(self.application().state, ApplicationState.UNREADABLE)
