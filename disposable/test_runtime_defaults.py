"""S7 needs real CLI interpreters and running-site identities that replay cannot establish."""

import json
import shlex

from django.test import tag

from operations.inputs import PreparationInputs
from runtimes import defaults
from runtimes.catalog import architecture_of, load
from sites.change import CREATE_SITE

from .runtime_defaults_testing import DefaultChangeCase
from .scenario_testing import SCENARIO_TAG


@tag(SCENARIO_TAG)
class RuntimeDefaultValidators(DefaultChangeCase):
    layer = "L1"
    prefix = "v339"
    validator = True

    def test_foreign_php_refuses_before_any_command_or_wrapper_change(self) -> None:
        before = self.native(
            "find /usr/local/bin -maxdepth 1 -printf '%f %l\\n' | sort; "
            "test ! -e /usr/local/libexec/barectl/defaults"
        )
        self.native("test ! -e /usr/local/bin/php")
        self.addCleanup(self.native, "rm -f /usr/local/bin/php")
        outcome, _ = self.apply_change(
            defaults.SET_DEFAULT_PHP,
            PreparationInputs("php84"),
            before_submit=(
                "printf '#!/bin/sh\\nexit 17\\n' >/usr/local/bin/php; chmod 755 /usr/local/bin/php"
            ),
        )
        self.assertEqual(outcome.result_class, "refused")
        self.assertEqual(outcome.reason, "evidence")
        self.native(
            "test ! -e /usr/local/bin/composer; test ! -e /usr/local/bin/wp; "
            "test ! -e /usr/local/libexec/barectl/defaults; grep -q 'exit 17' /usr/local/bin/php"
        )
        architecture = architecture_of(self.native("uname -m").strip())
        if architecture is None:
            self.fail("Unsupported native architecture.")
        with self.shell() as shell:
            observed = defaults.observations(defaults.read(shell, architecture))
        self.assertIn("administrator", observed.php_problem)
        self.native("rm /usr/local/bin/php")
        self.assertEqual(
            self.native(
                "find /usr/local/bin -maxdepth 1 -printf '%f %l\\n' | sort; "
                "test ! -e /usr/local/libexec/barectl/defaults"
            ),
            before,
        )


@tag(SCENARIO_TAG)
class ServerRuntimeDefaults(DefaultChangeCase):
    layer = "L1"
    exclusive = True
    prefix = "s7defaults"
    records: tuple[str, ...] = ("runtime-defaults-26.04",)

    def test_defaults_execute_selected_interpreters_and_preserve_existing_sites(self) -> None:
        outcome, _ = self.apply_change(
            CREATE_SITE, PreparationInputs("php84", "s7defaults", ("s7defaults.example.com",))
        )
        self.assertEqual(outcome.result_class, "succeeded")
        before = self.site_state()
        for entry, version in (("php84", "8.4."), ("php85", "8.5.")):
            outcome, _ = self.apply_change(defaults.SET_DEFAULT_PHP, PreparationInputs(entry))
            self.assertEqual(outcome.result_class, "succeeded")
            self.assertIn(
                version, self.native("PATH=/usr/local/bin:/usr/bin:/bin php -r 'echo PHP_VERSION;'")
            )
            self.assertEqual(
                self.native("readlink -f /usr/local/bin/php").strip(),
                self.native(f"readlink -f /nix/var/nix/profiles/barectl/{entry}/bin/php").strip(),
            )
            self.assertIn(
                "Composer version 2.10.3",
                self.native(
                    "runuser -u nobody -- env PATH=/usr/local/bin:/usr/bin:/bin "
                    "composer --version --no-ansi"
                ),
            )
            self.assertIn(
                "Composer version 2.10.3",
                self.native("PATH=/usr/local/bin:/usr/bin:/bin composer --version --no-ansi"),
            )
            fixture = json.dumps(
                {
                    "name": "barectl/offline-identity",
                    "scripts": {
                        "identity": '@php -r "echo PHP_BINARY;"',
                        "helpers": "git init --quiet && git --version && unzip -v",
                    },
                }
            )
            self.native(
                "install -d -m 700 /run/s7defaults-composer; printf %s "
                + shlex.quote(fixture)
                + " >/run/s7defaults-composer/composer.json"
            )
            command = (
                "cd /run/s7defaults-composer && COMPOSER_ALLOW_SUPERUSER=1 "
                "COMPOSER_DISABLE_NETWORK=1 PATH=/usr/local/bin:/usr/bin:/bin composer run "
            )
            self.assertIn(
                self.native(f"readlink -f /nix/var/nix/profiles/barectl/{entry}/bin/php").strip(),
                self.native(command + "identity --no-plugins"),
            )
            self.assertIn(
                "git version",
                self.native(command + "helpers --no-plugins"),
            )
            info = self.native("PATH=/usr/local/bin:/usr/bin:/bin wp --allow-root --info")
            self.assertIn(version, info)
            self.assertIn(
                self.native(f"readlink -f /nix/var/nix/profiles/barectl/{entry}/bin/php").strip(),
                info,
            )

            self.assertEqual(self.site_state(), before)
        architecture = architecture_of(self.native("uname -m").strip())
        if architecture is None:
            self.fail("Unsupported native architecture.")
        for entry, version in (("nodejs_22", "v22."), ("nodejs_24", "v24.")):
            path = next(
                build.path for build in load().offered(architecture) if build.entry == entry
            )
            self.native(
                "/nix/var/nix/profiles/default/bin/nix-store --realise "
                + path
                + " --option max-jobs 0 --option fallback false >/dev/null; "
                "/nix/var/nix/profiles/default/bin/nix-env --profile /nix/var/nix/profiles/barectl/"
                + entry
                + " --set "
                + path
            )
            outcome, _ = self.apply_change(defaults.SET_DEFAULT_NODE, PreparationInputs(entry))
            self.assertEqual(outcome.result_class, "succeeded")
            self.assertIn(version, self.native("PATH=/usr/local/bin:/usr/bin:/bin node --version"))
            expected = self.native(
                f"readlink -f /nix/var/nix/profiles/barectl/{entry}/bin/node"
            ).strip()
            self.assertEqual(
                self.native("PATH=/usr/local/bin:/usr/bin:/bin node -p process.execPath").strip(),
                expected,
            )
            fixture = json.dumps(
                {
                    "name": "offline-default-identity",
                    "version": "1.0.0",
                    "scripts": {"identity": "node identity.js"},
                    "bin": {"offline-default-identity": "identity.js"},
                }
            )
            self.native(
                "install -d -m 755 /run/s7defaults-node; printf %s "
                + shlex.quote(fixture)
                + " >/run/s7defaults-node/package.json; printf %s "
                + shlex.quote(
                    "#!/usr/bin/env node\nconsole.log(process.execPath);\n"
                    "console.log(process.env.npm_config_user_agent);\n"
                )
                + " >/run/s7defaults-node/identity.js; chmod 755 /run/s7defaults-node/identity.js"
            )
            prefix = (
                "cd /run/s7defaults-node && PATH=/usr/local/bin:/usr/bin:/bin "
                "npm_config_update_notifier=false npm_config_audit=false npm_config_fund=false "
            )
            npm_output = self.native(prefix + "npm run identity --offline --ignore-scripts=false")
            npx_output = self.native(
                prefix + "npx --offline --yes --package=./ offline-default-identity"
            )
            for output in (npm_output, npx_output):
                self.assertIn(expected, output)
                self.assertIn("node/" + version, output)
            self.assertEqual(self.site_state(), before)
        with self.shell() as shell:
            from discovery.observations import collect

            snapshot = collect(shell)
            observed = snapshot.runtime_defaults
            if observed is None:
                self.fail("Fresh discovery did not reconstruct the default commands.")
            self.checkpoint("runtime-defaults-26.04", shell)
        self.assertEqual((observed.php, observed.node), ("php85", "nodejs_24"))

    def site_state(self) -> str:
        return self.native(
            "find /var/www/s7defaults /etc/php-fpm -type f -exec sha256sum {} + | sort; "
            "find /var/www/s7defaults/bin -printf '%p %u %g %m %l\\n' | sort; "
            "stat -c '%n %i %u %g %a' /run/php-fpm/php84/s7defaults.sock; "
            "systemctl show php-fpm@php84.service php-fpm@php85.service "
            "-p MainPID -p ActiveEnterTimestampMonotonic -p ExecMainStartTimestampMonotonic"
        )
