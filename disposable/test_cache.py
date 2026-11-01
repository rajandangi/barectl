"""A site's own object cache, WordPress and Laravel (#391, #393).

docs/quality.md#native-layer. The lane server reaches only its lane's pinned snapshot. The
WordPress classes start from L1, create one site through the product so a PHP master and a
site proxy are running, then prove the transaction's ``daemon-reload`` recovery on those real
units (issue #428) and the cache lifecycle. The Laravel class starts from the prepared L5
snapshot so the cache lifecycle alone stays one small item.
"""

import os
import shlex
from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast, override

from django.test import tag

from discovery.observations import collect
from discovery.snapshot import CollectedSnapshot, ObservedCache
from discovery.ssh import RemoteShell
from operations.engine import ChangeKind, ReviewDraft
from operations.inputs import PreparationInputs

from . import mirror
from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase
from .test_laravel_deploy import LaravelDeployCase

STATE = "valkey-installed-26.04"
PACKAGE = "valkey-server"
MIRRORED_VERSION = "9.0.4"
SITE = "scachebase"
DOMAIN = "scachebase.example.com"
RUNNING_UNITS = (
    "php-fpm@php84.service",
    "php-fpm@php85.service",
    f"haproxy-site@{SITE}.service",
    f"php-fpm-site-php84@{SITE}.service",
)


def write(test: ScenarioTestCase, shell: RemoteShell, path: str, content: str) -> None:
    result = shell.run(f"install -D -m 0644 /dev/stdin {shlex.quote(path)}", stdin=content.encode())
    test.assertEqual(result.exit_status, 0, result.stdout)


class ValkeyCase(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "scache"

    def router(self, shell: RemoteShell) -> None:
        write(self, shell, "/etc/apt/sources.list.d/barectl-fixture.sources", mirror.apt_sources())
        write(
            self,
            shell,
            "/etc/apt/apt.conf.d/99barectl-fixture",
            'Acquire::By-Hash "no";\nAcquire::Languages "none";\n',
        )
        self.assertEqual(shell.run("rm -f /etc/apt/sources.list.d/ubuntu.sources").exit_status, 0)
        update = shell.run("apt-get update 2>&1")
        self.assertEqual(update.exit_status, 0, update.stdout)

    def review(self, shell: RemoteShell, kind: ChangeKind) -> ReviewDraft:
        inputs = PreparationInputs()
        return kind.review(kind.inspect(shell, inputs), inputs)

    def invocations(self) -> dict[str, str]:
        """The invocation of each running unit the package transaction will unbind."""
        running: dict[str, str] = {}
        for unit in RUNNING_UNITS:
            state = self.native(f"systemctl is-active {unit} || true").strip()
            if state == "active":
                running[unit] = self.native(
                    f"systemctl show -p InvocationID --value {unit}"
                ).strip()
        return running


@tag(SCENARIO_TAG)
class ValkeyInstall(ValkeyCase):
    records: tuple[str, ...] = (STATE,)

    def test_1_installs_masks_and_keeps_running_units_verifiable(self) -> None:
        from cache import engine as kinds
        from sites import change as site_change

        apply_change(
            self,
            site_change.CREATE_SITE,
            PreparationInputs("php84", SITE, (DOMAIN,)),
            timeout=60,
        )
        with self.shell() as shell:
            prepared = collect(shell)
        before_site = {site.identifier: site for site in prepared.sites.value}[SITE]
        self.assertEqual(before_site.state.value, "managed", before_site.missing)
        before = self.invocations()
        self.assertGreaterEqual(len(before), 3, before)
        with self.shell() as shell:
            self.router(shell)
            draft = self.review(shell, kinds.INSTALL)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertEqual([effect.scope.value for effect in draft.effects], ["server"])
            details = cast(list[dict[str, str]], draft.document["details"])
            listed = {item["label"]: item["value"] for item in details}
            self.assertTrue(
                listed["Package transaction"].startswith(f"{PACKAGE} {MIRRORED_VERSION}")
            )
            self.assertNotIn(listed["Download size"], {"", "Not reported."})
            self.assertGreater(cast(int, draft.document["download_bytes"]), 0)
        apply_change(self, kinds.INSTALL, PreparationInputs(), timeout=120)

        self.assertEqual(
            self.native(f"dpkg-query -W -f='${{Version}}' {PACKAGE}").strip(),
            cast(list[list[str]], draft.document["roots"])[0][1],
        )
        for property_name, expected in (
            ("LoadState", "masked"),
            ("UnitFileState", "masked"),
            ("ActiveState", "inactive"),
        ):
            with self.subTest(property=property_name):
                self.assertEqual(
                    self.native(
                        f"systemctl show -p {property_name} --value {PACKAGE}.service"
                    ).strip(),
                    expected,
                )
        self.assertEqual(self.native("ss -Hltn 'sport = :6379'").strip(), "")

        # #428: the package transaction's daemon-reload unbinds running units, so the change
        # restarts exactly the ones it affected and discovery verifies them again.
        after = self.invocations()
        self.assertEqual(set(after), set(before), after)
        for unit, invocation in before.items():
            with self.subTest(unit=unit):
                self.assertNotEqual(after[unit], invocation)

        served = self.native(
            "curl --fail --silent -H 'Host: scachebase.example.com' http://127.0.0.1/"
        )
        self.assertIn(SITE, served)

        with self.shell() as shell:
            # The transcript holds the installed state's review and full discovery, so a
            # fresh controller replays the same reads the fast layer proves.
            self.review(shell, kinds.INSTALL)
            observed = collect(shell)
            self.checkpoint(STATE, shell)
        sites = {site.identifier: site for site in observed.sites.value}
        if SITE not in sites:
            reasons = observed.standing.reasons if observed.standing is not None else ()
            self.fail("The prepared site was not read after the install: " + "; ".join(reasons))
        self.assertEqual(sites[SITE].state.value, "managed", sites[SITE].missing)
        problems = {
            runtime.entry: runtime.problem for runtime in observed.runtimes if runtime.problem
        }
        self.assertEqual(problems, {})
        from cache import observation

        current = observation.installed(observed)
        if current is None:
            self.fail("Discovery does not report Valkey as installed.")
        self.assertTrue(current.masked)
        self.assertTrue(current.inactive)

    def test_2_a_second_review_proposes_no_changes(self) -> None:
        from cache import engine as kinds

        with self.shell() as shell:
            draft = self.review(shell, kinds.INSTALL)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.effects)
        self.assertIn("already installed", str(draft.document["note"]))

    def test_3_a_fresh_controller_reconstructs_installed_masked_valkey(self) -> None:
        from cache import observation

        with self.shell() as shell:
            observed = collect(shell, sites=False)
        current = observation.installed(observed)
        if current is None:
            self.fail("A fresh controller does not reconstruct Valkey.")
        self.assertTrue(current.version.startswith(MIRRORED_VERSION))
        self.assertTrue(current.managed)
        self.assertTrue(current.masked)
        self.assertTrue(current.inactive)


OBJECT_CACHE_STATE = "object-cache-26.04"
OBJECT_CACHE_EDITED_STATE = "object-cache-edited-26.04"


@tag(SCENARIO_TAG)
class SiteObjectCache(ValkeyCase):
    """C1 part 1: one WordPress site's own cache, isolated, edited, and turned off."""

    layer = "L4"
    exclusive = True
    prefix = "l3wordpress"
    records: tuple[str, ...] = (OBJECT_CACHE_STATE, OBJECT_CACHE_EDITED_STATE)

    @property
    def site(self) -> str:
        from .wordpress_testing import WORDPRESS_SITE

        return WORDPRESS_SITE

    @property
    def other(self) -> str:
        from .test_prepared_wordpress import OTHER_SITE

        return OTHER_SITE

    @override
    @contextmanager
    def shell(self) -> Iterator[RemoteShell]:
        """A plain connection: setup applies reviewed changes a recording shell refuses."""
        from discovery import ssh

        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            yield connection

    def status(self, command: str) -> str:
        return self.native("{ " + command + "; } 2>&1 || true").strip()

    def as_site(self, *arguments: str) -> str:
        command = " ".join(shlex.quote(argument) for argument in arguments)
        return self.native(f"runuser -u s{self.site} -- {command}")

    def valkey(self, *arguments: str) -> str:
        socket = f"/run/valkey/{self.site}/valkey.sock"
        return self.status(
            f"runuser -u s{self.site} -- /usr/bin/valkey-cli -s {socket} "
            + " ".join(shlex.quote(argument) for argument in arguments)
            + "; printf 'status=%s' $?"
        )

    def wp(self, *arguments: str) -> str:
        return self.as_site(
            f"/var/www/{self.site}/bin/wp",
            f"--path=/var/www/{self.site}/current/public",
            *arguments,
        )

    def constant_lines(self) -> str:
        return self.native(
            f'grep -E "WP_REDIS_(SCHEME|PATH|PREFIX)" '
            f"/var/www/{self.site}/private/wp-config.php || true"
        ).strip()

    def dropin(self) -> bool:
        return (
            self.native(
                f"test -f /var/www/{self.site}/current/public/wp-content/object-cache.php "
                "&& echo present || true"
            ).strip()
            == "present"
        )

    def record(self, state: str) -> tuple[CollectedSnapshot, ReviewDraft]:
        from cache import instance
        from discovery import recorded, ssh
        from operations.inputs import PreparationInputs

        with ssh.connect(self.target()) as connection:
            shell = recorded.RecordingShell(connection, state, secrets=(recorded.SEEDED_SECRET,))
            collected = collect(shell)
            inputs = PreparationInputs(identifier=self.site)
            draft = instance.review(instance.inspect(shell, inputs), inputs)
            self.checkpoint(state, shell)
        return collected, draft

    def cache_row(self, collected: CollectedSnapshot) -> ObservedCache:
        return next(row for row in collected.cache.value if row.identifier == self.site)

    def test_1_turns_on_the_site_cache_and_proves_it_is_private(self) -> None:
        from cache import instance
        from operations.inputs import PreparationInputs

        # L4 already carries Valkey and the site's PHP client; their own scenarios prove
        # those installs (#391, #390).
        apply_change(
            self,
            instance.SET_SITE_OBJECT_CACHE,
            PreparationInputs(identifier=self.site, object_cache=True, cache_mib=64),
            timeout=120,
        )
        self.assertEqual(
            self.native(f"systemctl is-active valkey-server@{self.site}.service").strip(),
            "active",
        )
        socket = self.native(f"stat -c '%U %a %F' /run/valkey/{self.site}/valkey.sock").strip()
        self.assertEqual(socket, f"s{self.site} 600 socket")
        self.assertIn("PONG", self.valkey("PING"))
        self.assertIn("status=0", self.valkey("FLUSHALL"))
        self.assertIn("NOPERM", self.valkey("CONFIG", "SET", "maxmemory", "1"))
        self.assertIn("NOPERM", self.valkey("MODULE", "LIST"))
        status = self.wp("redis", "status")
        self.assertIn("Status: Connected", status)
        self.assertIn("Client: PhpRedis", status)
        self.assertIn("Drop-in: Valid", status)
        self.assertIn("Plugin Version: 3.0.0", status)
        self.assertTrue(self.dropin())
        lines = self.constant_lines()
        self.assertIn("WP_REDIS_SCHEME', 'unix'", lines)
        self.assertIn(f"WP_REDIS_PATH', '/run/valkey/{self.site}/valkey.sock'", lines)
        self.assertIn(f"WP_REDIS_PREFIX', 's{self.site}:'", lines)
        # Another site's account can neither open the connection nor read the configuration.
        refused = self.status(
            f"runuser -u s{self.other} -- /usr/bin/valkey-cli -s "
            f"/run/valkey/{self.site}/valkey.sock PING"
        )
        self.assertIn("Could not connect to Valkey", refused)
        self.assertIn("Permission denied", refused)
        self.assertIn(
            "Permission denied",
            self.status(f"runuser -u s{self.other} -- cat /etc/valkey/{self.site}.conf"),
        )
        collected, draft = self.record(OBJECT_CACHE_STATE)
        row = self.cache_row(collected)
        self.assertEqual(row.state, "on", row.problem)
        self.assertTrue(draft.eligible, draft.refusals)

    def test_2_a_repeated_review_proposes_nothing(self) -> None:
        from cache import instance
        from operations.inputs import PreparationInputs

        inputs = PreparationInputs(identifier=self.site, object_cache=True, cache_mib=64)
        with self.shell() as shell:
            draft = instance.review(instance.inspect(shell, inputs), inputs)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.effects, ())

    def test_3_a_supported_hand_edit_is_adopted_and_an_unsupported_one_is_reported(self) -> None:
        from cache import instance
        from operations.inputs import PreparationInputs

        config = f"/etc/valkey/{self.site}.conf"
        drop_in = f"/etc/systemd/system/valkey-server@{self.site}.service.d/barectl.conf"
        unit = f"valkey-server@{self.site}.service"
        self.native(f"sed -i 's/^maxmemory .*/maxmemory 134217728/' {config}")
        self.native(f"systemctl restart {unit}")
        inputs = PreparationInputs(identifier=self.site, object_cache=True, cache_mib=128)
        with self.shell() as shell:
            collected = collect(shell)
            draft = instance.review(instance.inspect(shell, inputs), inputs)
        self.assertEqual(self.cache_row(collected).state, "on")
        self.assertTrue(draft.no_changes, draft.refusals)
        self.native(f"sed -i 's/^User=.*/User=root/' {drop_in}")
        self.native(f"systemctl restart {unit}")
        with self.shell() as shell:
            collected = collect(shell)
            refused = instance.review(
                instance.inspect(shell, PreparationInputs(identifier=self.site)),
                PreparationInputs(identifier=self.site, object_cache=True, cache_mib=128),
            )
        self.assertEqual(self.cache_row(collected).state, "unsupported")
        self.assertFalse(refused.eligible)
        self.assertIn("outside supported settings", " ".join(refused.refusals))
        self.record(OBJECT_CACHE_EDITED_STATE)
        self.native(f"sed -i 's/^User=.*/User=s{self.site}/' {drop_in}")
        self.native(f"sed -i 's/^maxmemory .*/maxmemory 67108864/' {config}")
        self.native(f"systemctl restart {unit}")
        self.assertEqual(
            self.native(f"systemctl show --value -p User {unit}").strip(), f"s{self.site}"
        )

    def test_4_a_fresh_controller_reconstructs_the_cache_and_the_settings(self) -> None:
        from cache import instance
        from operations.inputs import PreparationInputs

        inputs = PreparationInputs(identifier=self.site, object_cache=True, cache_mib=64)
        with self.shell() as shell:
            collected = collect(shell)
            draft = instance.review(instance.inspect(shell, inputs), inputs)
        row = self.cache_row(collected)
        self.assertEqual(row.state, "on", row.problem)
        self.assertEqual(row.memory_mib, 64)
        self.assertEqual(row.plugin_version, "3.0.0")
        self.assertEqual(row.client, "phpredis")
        self.assertTrue(draft.no_changes, draft.refusals)

    def test_5_turning_it_off_leaves_no_instance_dropin_or_constants(self) -> None:
        from cache import instance
        from operations.inputs import PreparationInputs

        apply_change(
            self,
            instance.SET_SITE_OBJECT_CACHE,
            PreparationInputs(identifier=self.site, object_cache=False),
            timeout=120,
        )
        self.assertNotEqual(
            self.status(f"systemctl show --value -p ActiveState valkey-server@{self.site}.service"),
            "active",
        )
        for path in (
            f"/etc/valkey/{self.site}.conf",
            f"/var/lib/valkey/{self.site}",
            f"/run/valkey/{self.site}",
            f"/etc/systemd/system/valkey-server@{self.site}.service.d",
            f"/var/www/{self.site}/current/public/wp-content/object-cache.php",
        ):
            self.assertFalse(self.native(f"test -e {path} && echo present || true").strip(), path)
        self.assertEqual(self.constant_lines(), "")
        with self.shell() as shell:
            collected = collect(shell)
        self.assertEqual(self.cache_row(collected).state, "off")


LARAVEL_CACHE_STATE = "object-cache-laravel-26.04"
LARAVEL_CACHE_SITE = "sqwalpha"
LARAVEL_CACHE_DOMAIN = "site.fixture.test"


@tag(SCENARIO_TAG)
class LaravelObjectCache(LaravelDeployCase):
    """#393 on the prepared L5 layer: the cache lifecycle only, no setup."""

    layer = "L5"
    exclusive = True
    prefix = "sqw"
    identity = LARAVEL_CACHE_SITE
    domain = LARAVEL_CACHE_DOMAIN
    records: tuple[str, ...] = (LARAVEL_CACHE_STATE,)

    @override
    @contextmanager
    def shell(self) -> Iterator[RemoteShell]:
        os.environ["SSH_AUTH_SOCK"] = ""
        from discovery import ssh

        with ssh.connect(self.target()) as connection:
            yield connection

    def environment(self) -> str:
        return self.native(f"cat {self.base()}/private/laravel.env")

    def valkey(self, *arguments: str) -> str:
        command = " ".join(shlex.quote(argument) for argument in arguments)
        return self.native(
            f"runuser -u s{LARAVEL_CACHE_SITE} -- /usr/bin/valkey-cli -s "
            f"/run/valkey/{LARAVEL_CACHE_SITE}/valkey.sock " + command
        ).strip()

    def cached_values(self) -> list[str]:
        """What the instance holds, read out of band from whichever database Laravel used."""
        databases = {0}
        for line in self.valkey("INFO", "keyspace").splitlines():
            if line.startswith("db") and ":" in line:
                databases.add(int(line[2:].split(":", 1)[0]))
        values: list[str] = []
        for database in sorted(databases):
            keys = self.valkey(
                "-n", str(database), "--scan", "--pattern", "*barectl-cache-check*"
            ).splitlines()
            values.extend(self.valkey("-n", str(database), "GET", key) for key in keys)
        return values

    def test_the_application_reads_through_the_socket_and_returns(self) -> None:
        from cache import instance
        from discovery import recorded, ssh
        from discovery.observations import collect

        self.assertIn("CACHE_STORE=database", self.environment())
        before = {
            process: self.native(
                "systemctl show --value -p InvocationID "
                f"barectl-site-{LARAVEL_CACHE_SITE}-queue{process}.service"
            ).strip()
            for process in (1, 2)
        }
        apply_change(
            self,
            instance.SET_SITE_OBJECT_CACHE,
            PreparationInputs(identifier=LARAVEL_CACHE_SITE, object_cache=True, cache_mib=64),
            timeout=180,
        )
        environment = self.environment()
        self.assertIn("CACHE_STORE=redis", environment)
        self.assertIn(f"REDIS_HOST=/run/valkey/{LARAVEL_CACHE_SITE}/valkey.sock", environment)
        self.assertIn("REDIS_PORT=0", environment)
        self.assertEqual(self.https_status("/"), 200)
        self.assertEqual(self.https_body("/"), "through-the-private-cache")
        # The instance keeps Laravel's serialized value; the store name is not the proof.
        self.assertTrue(any("through-the-private-cache" in value for value in self.cached_values()))
        for process in (1, 2):
            self.assertNotEqual(
                self.native(
                    "systemctl show --value -p InvocationID "
                    f"barectl-site-{LARAVEL_CACHE_SITE}-queue{process}.service"
                ).strip(),
                before[process],
            )
        with ssh.connect(self.target()) as connection:
            recording = recorded.RecordingShell(
                connection, LARAVEL_CACHE_STATE, secrets=(recorded.SEEDED_SECRET,)
            )
            observed = collect(recording)
            inputs = PreparationInputs(
                identifier=LARAVEL_CACHE_SITE, object_cache=True, cache_mib=64
            )
            instance.review(instance.inspect(recording, inputs), inputs)
            self.checkpoint(LARAVEL_CACHE_STATE, recording)
        row = next(item for item in observed.cache.value if item.identifier == LARAVEL_CACHE_SITE)
        self.assertEqual(row.state, "on", row.problem)
        apply_change(
            self,
            instance.SET_SITE_OBJECT_CACHE,
            PreparationInputs(
                identifier=LARAVEL_CACHE_SITE,
                object_cache=False,
                cache_store_known=True,
                cache_store_present=True,
                cache_store="database",
            ),
            timeout=180,
        )
        environment = self.environment()
        self.assertIn("CACHE_STORE=database", environment)
        self.assertNotIn("REDIS_HOST", environment)
        self.assertNotIn("REDIS_PORT", environment)
        self.assertNotEqual(
            self.native(
                f"systemctl show -p ActiveState --value valkey-server@{LARAVEL_CACHE_SITE}.service"
            ).strip(),
            "active",
        )
        self.assertEqual(
            self.native(f"test -e /run/valkey/{LARAVEL_CACHE_SITE}/valkey.sock; echo $?").strip(),
            "1",
        )
        self.assertEqual(self.https_status("/"), 200)
        self.assertEqual(self.https_body("/"), "through-the-private-cache")
        with self.shell() as shell:
            after = collect(shell)
        row = next(item for item in after.cache.value if item.identifier == LARAVEL_CACHE_SITE)
        self.assertEqual(row.state, "off")
