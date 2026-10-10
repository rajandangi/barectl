"""Approved-source native site fixture (docs/wordpress-source-qualification.md)."""

from django.contrib.auth.models import Permission

from bootstrap import php_supply
from bootstrap.apply_remote_testing import ApplyAcceptanceTestCase
from bootstrap.models import Action, ConfigurationPlan, Verification
from bootstrap.php_source_testing import trust_fixture
from discovery.fakes import run_worker
from discovery.services import request_discovery
from sites.convention import Stage, render_pool, render_site

from . import qualification_testing
from .install_remote_testing import (
    IDENTIFIER,
    NAMES,
    InstallationServerCase,
    cleanups,
    prepared_server,
    put,
)


def prepare_source_site(case: InstallationServerCase) -> None:
    ApplyAcceptanceTestCase.setUp(case)
    branch = case.php
    release = case.administer(". /etc/os-release; echo $VERSION_ID").strip()
    architecture = case.administer("dpkg --print-architecture").strip()
    case.enterContext(
        qualification_testing.source_candidate_qualified(release, architecture, branch)
    )
    trust_fixture(case, case.administer)
    for codename in (
        "view_configurationplan",
        "prepare_configurationplan",
        "apply_configurationplan",
        "prepare_tlsplan",
        "apply_tlsplan",
        "issue_certificate",
        "view_tlsplan",
    ):
        case.user.user_permissions.add(Permission.objects.get(codename=codename))
    case.administer(
        "set -e; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gpg >/dev/null; "
        "p=$(dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n' 'php*' 2>/dev/null "
        "| awk '$2 != \"un\" {print $1}'); "
        'if [ -n "$p" ]; then DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $p >/dev/null; fi'
    )
    case.addCleanup(
        case.administer,
        f"rm -f {php_supply.SOURCE_FILE} {php_supply.KEY_FILE} {php_supply.PREFERENCE_FILE}; true",
    )
    source = case.apply(case.plan(Action.PHP_SOURCE))
    case.assertEqual(source.verification, Verification.PASSED, source.failure)
    refresh = case.apply(case.plan(Action.METADATA_REFRESH))
    case.assertEqual(refresh.verification, Verification.PASSED, refresh.failure)
    case.client.post(
        f"/servers/{case.server.pk}/plans/prepare/",
        {"action": Action.PHP, "php_version": branch, "php_supply": "sury"},
    )
    run_worker()
    installed = case.apply(ConfigurationPlan.objects.latest("pk"))
    case.assertEqual(installed.verification, Verification.PASSED, installed.failure)
    for cleanup in cleanups(branch):
        case.addCleanup(case.administer, cleanup)
    library_plan = case.plan(Action.WORDPRESS_LIBRARIES)
    case.assertTrue(library_plan.eligible, case.texts(library_plan))
    case.assertEqual(library_plan.php_supply, "ubuntu")
    if not library_plan.no_changes:
        libraries = case.apply(library_plan)
        case.assertEqual(libraries.verification, Verification.PASSED, libraries.failure)
    case.assertTrue(case.plan(Action.WORDPRESS_LIBRARIES).no_changes)
    for command in prepared_server(branch)[1:]:
        case.administer(command)
    case.administer(
        put(
            f"/etc/nginx/sites-available/{IDENTIFIER}.conf",
            render_site(IDENTIFIER, NAMES, ipv6=True, stage=Stage.REDIRECT, php_version=branch),
            "root",
            "root",
            "644",
        )
        + " && "
        + put(
            f"/etc/php/{branch}/fpm/pool.d/{IDENTIFIER}.conf",
            render_pool(IDENTIFIER, php_version=branch),
            "root",
            "root",
            "644",
        )
        + f" && php-fpm{branch} -t && systemctl reload php{branch}-fpm"
        + " && nginx -t -q && systemctl reload nginx"
        + f" && for n in $(seq 50); do test -S /run/php/sshop-php{branch}.sock "
        + f"&& break; sleep 0.2; done; test -S /run/php/sshop-php{branch}.sock"
    )
    request_discovery(case.server)
    run_worker()
    case.client.post(f"/servers/{case.server.pk}/sites/{IDENTIFIER}/wordpress/runtime/prepare/")
    run_worker()
    runtime = ConfigurationPlan.objects.latest("pk")
    case.assertTrue(runtime.eligible, case.texts(runtime))
    case.assertEqual((runtime.php_version, runtime.php_supply), (branch, "sury"))
    case.assertFalse(runtime.no_changes)
    baseline = case.apply(runtime)
    case.assertEqual(baseline.verification, Verification.PASSED, baseline.failure)
    packages = " ".join(
        f"php{branch}-{suffix}"
        for suffix in ("cli", "fpm", "curl", "xml", "mbstring", "zip", "gd", "intl", "mysql")
    )
    versions = case.administer(
        "dpkg-query -W -f='${binary:Package} ${Version} ${Architecture}\\n' "
        f"{packages} libgd3 libsodium23"
    )
    print(  # noqa: T201 - native qualification package receipt
        f"WordPress source candidate: Ubuntu {release}, {architecture}, PHP {branch}\n{versions}"
    )
