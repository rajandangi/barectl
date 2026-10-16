"""Site serving identity and switches require actual native admission boundaries."""

import shlex

from django.test import tag

from operations.inputs import PreparationInputs
from sites.change import CREATE_SITE
from sites.php_change import SET_SITE_PHP

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class SitePHPServing(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s339serve"

    def test_created_site_uses_independent_private_proxy_and_fpm(self) -> None:
        try:
            apply_change(
                self,
                CREATE_SITE,
                PreparationInputs("php84", "s339serve", ("s339serve.example.com",)),
            )
        except AssertionError:
            self.fail(
                self.native(
                    "journalctl --no-pager -u 'barectl-apply-*' "
                    "-u haproxy-site@s339serve.service "
                    "-u php-fpm-site-php84@s339serve.service -n 60 -o cat"
                )
            )
        self.assertEqual(
            self.native(
                "systemctl show --value -p LoadState haproxy-site@s339serve.service"
            ).strip(),
            "loaded",
        )
        self.assertEqual(
            self.native("systemctl is-active php-fpm-site-php84@s339serve.service").strip(),
            "active",
        )
        self.assertEqual(
            self.native("stat -c '%U %G %a' /run/haproxy/s339serve/http.sock").strip(),
            "caddy caddy 600",
        )
        self.assertEqual(
            self.native("stat -c '%U %G %a' /run/php-fpm/sites/s339serve/php84/app.sock").strip(),
            "root ps339serve 660",
        )
        self.assertFalse(self.native("find /etc/php-fpm/php84/pools -name s339serve.conf").strip())

        self.native(
            "cat > /var/www/s339serve/current/public/index.php <<'PHP'\n"
            "<?php echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION.'|'."
            "($_SERVER['PATH_INFO'] ?? '').'|'.($_GET['abc'] ?? '').'|'."
            "($_SERVER['HTTP_PROXY'] ?? '').'|'.($_SERVER['HTTP_X_TEST'] ?? '');\nPHP"
        )
        self.assertEqual(
            self.native(
                "curl --fail --silent -H 'Host: s339serve.example.com' "
                "-H 'Proxy: forbidden' -H 'X-Test: preserved' "
                "'http://127.0.0.1/index.php/extra?abc=one'"
            ),
            "8.4|/extra|one||preserved",
        )
        self.native(
            "cat > /var/www/s339serve/current/canary.php <<'PHP'\n"
            "<?php file_put_contents('/var/www/s339serve/private/traversal-effect', 'ran'); "
            "echo 'PRIVATE_CANARY';\nPHP"
        )
        for path in (
            "/../canary.php",
            "/%2e%2e/canary.php",
            "/index.php/../../canary.php",
            "/index.php/%2e%2e/%2e%2e/canary.php",
            "/%252e%252e/canary.php",
            "/index.php/extra.php/../../canary.php",
        ):
            response = self.native(
                "curl --path-as-is --silent -H 'Host: s339serve.example.com' "
                + shlex.quote("http://127.0.0.1" + path)
            )
            self.assertNotIn("PRIVATE_CANARY", response, path)
        self.assertEqual(
            self.native(
                "if [ -e /var/www/s339serve/private/traversal-effect ]; then printf yes; "
                "else printf no; fi"
            ),
            "no",
        )
        self.assertEqual(
            self.native(
                "curl --path-as-is --fail --silent -H 'Host: s339serve.example.com' "
                "'http://127.0.0.1/index.php/extra.php?abc=three'"
            ),
            "8.4|/extra.php|three||",
        )
        proxy_identity = self.native(
            "systemctl show haproxy-site@s339serve.service caddy.service -p MainPID -p InvocationID"
        )
        for entry in ("php85", "php84"):
            apply_change(self, SET_SITE_PHP, PreparationInputs(entry, "s339serve"))
            self.assertEqual(
                self.native(f"systemctl is-active php-fpm-site-{entry}@s339serve.service").strip(),
                "active",
            )
            self.assertEqual(
                self.native(
                    "systemctl show haproxy-site@s339serve.service caddy.service "
                    "-p MainPID -p InvocationID"
                ),
                proxy_identity,
            )
            self.assertEqual(
                self.native(
                    "curl --fail --silent -H 'Host: s339serve.example.com' "
                    "'http://127.0.0.1/index.php/extra?abc=two'"
                ),
                ("8.5" if entry == "php85" else "8.4") + "|/extra|two||",
            )


@tag(SCENARIO_TAG)
class ForeignPHPAdmission(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s339foreign"

    def test_unrecognized_private_haproxy_process_blocks_management(self) -> None:
        from bootstrap import foundation
        from bootstrap.standing import Standing
        from discovery.observations import collect

        config = """global
    maxconn 8
    nbthread 1
    tune.quic.fe.sock-per-conn force-off
    tune.quic.fe.tx.udp-gso off
    tune.quic.be.tx.udp-gso off
defaults
    mode http
    timeout connect 1s
    timeout client 1s
    timeout server 1s
frontend foreign
    bind /run/s339foreign.sock
    http-request return status 200
"""
        self.native("printf %s " + shlex.quote(config) + " >/run/s339foreign.cfg")
        self.addCleanup(self.native, "rm -f /run/s339foreign.cfg /run/s339foreign.sock")
        self.addCleanup(self.native, "systemctl stop s339foreign.service")
        self.native(
            "systemd-run --unit=s339foreign --property=Type=exec -- "
            "/nix/var/nix/profiles/barectl/haproxy/bin/haproxy -f /run/s339foreign.cfg"
        )
        with self.shell() as shell:
            snapshot = collect(shell)
            self.assertIsNotNone(snapshot.standing)
            if snapshot.standing is None:
                self.fail("No host-standing evidence.")
            self.assertEqual(snapshot.standing.standing, Standing.NOT_MANAGEABLE)
            self.assertIn("Unrecognized HAProxy process", " ".join(snapshot.standing.reasons))
            draft = foundation.review(foundation.inspect(shell))
            self.assertFalse(draft.eligible)


@tag(SCENARIO_TAG)
class SitePHPIsolation(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s339isolate"

    def test_switch_preserves_two_other_private_site_services_and_data(self) -> None:
        import json
        import sys

        for suffix in ("alpha", "beta", "gamma"):
            identifier = self.prefix + suffix
            apply_change(
                self,
                CREATE_SITE,
                PreparationInputs("php84", identifier, (identifier + ".example.com",)),
            )
        units = " ".join(
            f"php-fpm-site-php84@{self.prefix}{suffix}.service "
            f"haproxy-site@{self.prefix}{suffix}.service"
            for suffix in ("beta", "gamma")
        )
        unchanged = (
            "systemctl show " + units + " -p MainPID -p InvocationID; "
            "sha256sum /etc/haproxy/sites/s339isolate{beta,gamma}.cfg "
            "/var/lib/haproxy/sites/s339isolate{beta,gamma}.state "
            "/var/www/s339isolate{beta,gamma}/current/public/index.php "
            "/var/www/s339isolate{beta,gamma}/bin/{php,composer,wp}"
        )
        unchanged = "bash -c " + shlex.quote(unchanged)
        before = self.native(unchanged)
        pids = self.native("systemctl show --value -p MainPID " + units).split()
        self.assertEqual(len(set(pids)), 4)
        for suffix in ("beta", "gamma"):
            identifier = self.prefix + suffix
            probe = (
                "import socket; s=socket.socket(socket.AF_UNIX); "
                "s.connect('/run/php-fpm/sites/" + identifier + "/php84/app.sock')"
            )
            for account in ("caddy", "s" + identifier, "ps339isolatealpha"):
                denied = self.native(
                    "if "
                    + shlex.join(["runuser", "-u", account, "--", "python3", "-c", probe])
                    + " 2>/dev/null; then printf admitted; else printf denied; fi"
                )
                self.assertEqual(denied, "denied", (identifier, account))
        apply_change(self, SET_SITE_PHP, PreparationInputs("php85", "s339isolatealpha"))
        self.assertEqual(self.native(unchanged), before)
        for suffix in ("alpha", "beta", "gamma"):
            identifier = self.prefix + suffix
            response = json.loads(
                self.native(
                    "curl --fail --silent -H "
                    + shlex.quote("Host: " + identifier + ".example.com")
                    + " http://127.0.0.1/"
                )
            )
            self.assertEqual(response["uid"], int(self.native("id -u s" + identifier)))
            self.assertEqual(response["runtime"], "8.5" if suffix == "alpha" else "8.4")
        self.assert_runtime_isolation()
        resources = self.native(
            "for unit in $(systemctl list-units --no-legend --plain --type=service "
            "'haproxy-site@s339isolate*' 'php-fpm-site-*@s339isolate*' | awk '{print $1}'); do "
            'group=$(systemctl show --value -p ControlGroup "$unit"); '
            'for pid in $(cat "/sys/fs/cgroup$group/cgroup.procs"); do '
            "awk '/^Pss:/{print $2}' /proc/\"$pid\"/smaps_rollup; done; done"
        )
        measured = sum(int(value) for value in resources.split())
        self.assertGreater(measured, 0)
        sys.stdout.write("Three-site serving PSS KiB: " + str(measured) + "\n")

    def assert_runtime_isolation(self) -> None:
        """From alpha's own PHP worker every other site's private material is out of reach.

        ADR 0038 gives each site its own serving master. Alpha runs php85 while beta runs
        php84, so alpha's OPcache, sessions, files and admission socket are a different
        process, identity and directory tree. Positive controls prove the targets exist and
        answer their owners, so a missing path cannot masquerade as isolation.
        """
        import json

        alpha, beta = self.prefix + "alpha", self.prefix + "beta"
        script = f"""<?php header('Content-Type: application/json');
$root = '/var/www/{beta}';
$app = 'unix:///run/php-fpm/sites/{beta}/php84/app.sock';
$status = 'unix:///run/php-fpm/sites/{beta}/php84/status/listen.sock';
$proxy = 'unix:///run/haproxy/{beta}/http.sock';
$cached = @opcache_get_status(true);
$reset = @opcache_reset();
$result = [
  'uid' => posix_geteuid(),
  'runtime' => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
  'own_file' => @file_get_contents(__DIR__ . '/hello.txt'),
  'own_session' => is_array(@scandir(session_save_path())),
  'status_type' => gettype($cached),
  'reset' => $reset,
  'cross_file' => @file_get_contents($root . '/current/public/hello.txt'),
  'cross_session' => @scandir($root . '/private/sessions'),
  'cross_socket' => @stream_socket_client($app, $e, $m, 1) !== false,
  'cross_status' => @stream_socket_client($status, $e, $m, 1) !== false,
  'cross_proxy' => @stream_socket_client($proxy, $e, $m, 1) !== false,
];
echo json_encode($result);
"""
        self.native(
            f"cat > /var/www/{alpha}/current/public/isolation.php <<'PHP'\n" + script + "PHP\n"
        )
        owner = shlex.join(
            [
                "runuser",
                "-u",
                "p" + beta,
                "--",
                "python3",
                "-c",
                (
                    "import socket; s=socket.socket(socket.AF_UNIX); "
                    f"s.connect('/run/php-fpm/sites/{beta}/php84/app.sock')"
                ),
            ]
        )
        self.assertEqual(
            self.native(
                f"test -r /var/www/{beta}/current/public/hello.txt && "
                f"test -S /run/php-fpm/sites/{beta}/php84/app.sock && "
                f"test -d /var/www/{beta}/private/sessions && " + owner + " && printf ready"
            ),
            "ready",
            "the isolation targets must exist and answer their own owners",
        )
        response = json.loads(
            self.native(
                "curl --fail --silent -H "
                + shlex.quote("Host: " + alpha + ".example.com")
                + " http://127.0.0.1/isolation.php"
            )
        )
        self.assertEqual(response["uid"], int(self.native("id -u s" + alpha)))
        self.assertEqual(response["runtime"], "8.5")
        self.assertEqual(response["own_file"], "Welcome to your PHP site.\n")
        self.assertTrue(response["own_session"])
        self.assertNotEqual(response["status_type"], "array", "OPcache status must stay root-only")
        self.assertFalse(response["reset"], "OPcache reset must stay root-only")
        self.assertFalse(response["cross_file"])
        self.assertFalse(response["cross_session"])
        self.assertFalse(response["cross_socket"])
        self.assertFalse(response["cross_status"])
        self.assertFalse(response["cross_proxy"])
