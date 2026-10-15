"""A site's Node selection changes only its own native command links."""

import shlex
import tempfile
from pathlib import Path

from django.contrib.auth.models import Permission, User
from django.test import override_settings, tag

from operations import engine
from operations.inputs import PreparationInputs
from runtimes.change import ADD_RUNTIME
from sites.change import CREATE_SITE

from .change_testing import apply_change
from .runtime_defaults_testing import DefaultChangeCase
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class SiteNodeSelection(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s7node"
    records: tuple[str, ...] = ("site-node-26.04", "site-node-interrupted-26.04")

    def test_node_selection_reconstructs_and_leaves_php_and_site_content_unchanged(self) -> None:
        from sites.node_change import SET_SITE_NODE

        for entry in ("nodejs_22", "nodejs_24"):
            apply_change(self, ADD_RUNTIME, PreparationInputs(entry))
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs("php84", "s7node", ("s7node.example.com",)),
        )
        command = (
            "sha256sum /etc/caddy/sites/s7node.caddy "
            "/etc/php-fpm/sites/s7node/php84/pools/s7node.conf "
            "/var/www/s7node/current/public/index.php /var/www/s7node/bin/php "
            "/var/www/s7node/bin/composer /var/www/s7node/bin/wp "
            "/etc/haproxy/sites/s7node.cfg /var/lib/haproxy/sites/s7node.state; "
            "stat -c '%i %u %g %a' /run/php-fpm/sites/s7node/php84/app.sock; "
            "systemctl show php-fpm@php84.service php-fpm@php85.service "
            "php-fpm-site-php84@s7node.service haproxy-site@s7node.service "
            "-p MainPID -p InvocationID"
        )
        before = self.native(command)
        for entry, major in (("nodejs_24", "24"), ("nodejs_22", "22")):
            apply_change(self, SET_SITE_NODE, PreparationInputs(entry, "s7node"))
            self.assertEqual(self.native(command), before)
            self.assertEqual(
                self.native(
                    shlex.join(
                        ["/var/www/s7node/bin/node", "-p", "process.versions.node.split('.')[0]"]
                    )
                ).strip(),
                major,
            )
            for name in ("node", "npm", "npx"):
                self.assertEqual(
                    self.native("readlink " + shlex.quote("/var/www/s7node/bin/" + name)).strip(),
                    f"/nix/var/nix/profiles/barectl/{entry}/bin/{name}",
                )
            from discovery.observations import collect

            with self.shell() as fresh:
                sites = collect(fresh).sites.value
                site = next(site for site in sites if site.identifier == "s7node")
                self.assertEqual(site.node_runtime, entry)
        from sites import node_change, observation

        inputs = PreparationInputs("nodejs_24", "s7node")
        with self.shell() as shell:
            evidence = node_change.inspect(shell, inputs)
            engine._sites_digest(shell, node_change.review(evidence, inputs))
            self.checkpoint("site-node-26.04", shell)
        source = (
            observation.COMMON_SOURCE
            + "\nstart_site_fpm(setting('s7node', ['s7node.example.com'], 'php85'))\n"
        )
        self.native(shlex.join(["python3", "-c", source]))
        try:
            with self.shell() as fresh:
                evidence = node_change.inspect(fresh, inputs)
                draft = node_change.review(evidence, inputs)
                self.assertFalse(draft.eligible)
                self.assertIn("The PHP runtime transition is incomplete.", draft.refusals)
                if evidence.state is None:
                    self.fail("Interrupted native state disappeared.")
                matches = [
                    site
                    for site in evidence.state["native"]["sites"]
                    if site["identifier"] == "s7node"
                ]
                self.assertEqual(len(matches), 1)
                engine._sites_digest(fresh, draft)
                self.checkpoint("site-node-interrupted-26.04", fresh)
        finally:
            self.native(
                "systemctl stop php-fpm-site-php85@s7node.service; "
                "systemctl --no-reload disable php-fpm-site-php85@s7node.service; "
                "rm /etc/php-fpm/sites/s7node/php85/pools/s7node.conf "
                "/etc/php-fpm/sites/s7node/php85/php-fpm.conf "
                "/etc/php-fpm/sites/s7node/php85/php.ini; "
                "rmdir /etc/php-fpm/sites/s7node/php85/pools /etc/php-fpm/sites/s7node/php85"
            )


@tag(SCENARIO_TAG)
class SiteNodeValidators(DefaultChangeCase):
    layer = "L1"
    validator = True
    prefix = "s7nodevalidate"

    def test_held_site_deployment_lock_refuses_without_changing_site_links(self) -> None:
        from sites.node_change import SET_SITE_NODE

        apply_change(self, ADD_RUNTIME, PreparationInputs("nodejs_24"))
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs("php84", "s7nodevalidate", ("s7nodevalidate.example.com",)),
        )
        state_command = (
            "find /var/www/s7nodevalidate /etc/php-fpm -type f -exec sha256sum {} + | sort; "
            "find /var/www/s7nodevalidate/bin -printf '%p %u %g %m %l\\n' | sort; "
            "stat -c '%i %u %g %a' /run/php-fpm/sites/s7nodevalidate/php84/app.sock"
        )
        before = self.native(state_command)
        holder = (
            "systemd-run --collect --unit s7nodevalidate-holder -- /usr/bin/flock -x "
            "/var/www/s7nodevalidate/.deploy.lock /bin/sh -c "
            "'touch /run/s7nodevalidate-held; sleep 60'; "
            "for n in $(seq 1 100); do test -e /run/s7nodevalidate-held && break; sleep .02; done; "
            "test -e /run/s7nodevalidate-held"
        )
        try:
            result, _ = self.apply_change(
                SET_SITE_NODE,
                PreparationInputs("nodejs_24", "s7nodevalidate"),
                before_submit=holder,
            )
            self.assertEqual((result.result_class, result.reason), ("lock_busy", ""))
            self.assertEqual(self.native(state_command), before)
        finally:
            self.native(
                "systemctl stop s7nodevalidate-holder.service; rm -f /run/s7nodevalidate-held; "
                "rm -f /var/www/s7nodevalidate/bin/node /var/www/s7nodevalidate/bin/npm "
                "/var/www/s7nodevalidate/bin/npx"
            )

    def test_native_read_only_bin_failure_has_a_parseable_refusal_without_links(self) -> None:
        from sites.node_change import SET_SITE_NODE

        apply_change(self, ADD_RUNTIME, PreparationInputs("nodejs_24"))
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs("php84", "s7nodevalidate", ("s7nodevalidate.example.com",)),
        )
        from discovery.fakes import run_worker
        from operations.models import ChangeRun, Result, Verification
        from operations.services import request_apply, request_prepare
        from servers.models import Server
        from servers.registration import save_server

        target = self.target()
        with tempfile.TemporaryDirectory() as temporary:
            configuration = Path(temporary) / "config"
            configuration.write_text(
                f"Host node-validator\n  HostName {target.hostname}\n  Port {target.port}\n"
                f"  User {target.user}\n  IdentityFile {target.identity_files[0]}\n"
                f"  UserKnownHostsFile {target.known_hosts_files[0]}\n"
            )
            with override_settings(
                SSH_CONFIG_PATH=str(configuration),
                SSH_KNOWN_HOSTS_PATH=str(target.known_hosts_files[0]),
            ):
                operator = User.objects.create_user(username="node-operator")
                for name in ("view_server", "view_siteobservation", "view_changes", "change_site"):
                    operator.user_permissions.add(Permission.objects.get(codename=name))
                server = Server(name="Node failure", ssh_alias="node-validator")
                registrar = User.objects.create_superuser(username="node-registrar")
                save_server(server, user=registrar)
                run_worker()
                preparation = request_prepare(
                    server,
                    operator,
                    SET_SITE_NODE.slug,
                    inputs={
                        "version": 1,
                        "identifier": "s7nodevalidate",
                        "selection": "nodejs_24",
                    },
                )
                if preparation is None:
                    self.fail("No Node preparation was queued.")
                run_worker()
                preparation.refresh_from_db()
                self.assertEqual(preparation.status, "succeeded", preparation.failure)
                request = request_apply(preparation.review, operator)
                if request.run is None:
                    self.fail("No Node run was queued: " + request.problem)
                directory = "/var/www/s7nodevalidate/bin"
                self.native(
                    f"mount --bind {directory} {directory}; mount -o remount,bind,ro {directory}"
                )
                try:
                    run_worker()
                    applied = ChangeRun.objects.get(pk=request.run.pk)
                    self.assertEqual(applied.execution, Result.REFUSED, applied.failure)
                    self.assertEqual(applied.result_reason, "evidence")
                    self.assertEqual(applied.verification, Verification.NOT_APPLICABLE)
                    self.assertEqual(applied.status, "failed")
                    self.native(
                        f"test ! -e {directory}/node; test ! -e {directory}/npm; "
                        f"test ! -e {directory}/npx"
                    )
                finally:
                    self.native("umount " + directory)

    def test_post_review_foreign_command_refuses_before_creating_other_node_links(self) -> None:
        from sites.node_change import SET_SITE_NODE

        apply_change(self, ADD_RUNTIME, PreparationInputs("nodejs_24"))
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs("php84", "s7nodevalidate", ("s7nodevalidate.example.com",)),
        )
        result, _ = self.apply_change(
            SET_SITE_NODE,
            PreparationInputs("nodejs_24", "s7nodevalidate"),
            before_submit=(
                "printf administrator-command >/var/www/s7nodevalidate/bin/npx; "
                "chmod 755 /var/www/s7nodevalidate/bin/npx"
            ),
        )
        self.assertEqual((result.result_class, result.reason), ("refused", "precondition"))
        self.assertEqual(
            self.native("cat /var/www/s7nodevalidate/bin/npx"), "administrator-command"
        )
        self.native(
            "test ! -e /var/www/s7nodevalidate/bin/node; test ! -e /var/www/s7nodevalidate/bin/npm"
        )
