"""The Laravel Deploy, Roll back and failure fixtures, natively (Phase B #259).

docs/quality.md#native-layer. A site created by the product's own Create Laravel site change
is deployed from the lane's fixture Git host over credential-free HTTPS, with Composer dist
archives and HTTPS certificates from the lane. The scenarios prove the applied lifecycle
(fetch, build, link, migrate, switch, readiness, prune), the maintenance gate's failure
behaviour, a Roll back, the per-site migrations switch and one Deploy on PostgreSQL.
"""

import base64
import json
import os
import pathlib
import shlex
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast, override

from django.test import tag

from discovery import recorded, ssh
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import engine, native
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from sites.observation import python_command

from . import mirror
from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

MARIADB_SOCKET = "/run/mysqld/mysqld.sock"

_GOOD_VIEW = "landed-one\n"
_GOOD_CSS = "body { color: #123456; }\n"
_MIGRATION_SESSIONS = """<?php

use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
        Schema::create('cache', function (Blueprint $table) {
            $table->string('key')->primary();
            $table->mediumText('value');
            $table->integer('expiration');
        });
        Schema::create('cache_locks', function (Blueprint $table) {
            $table->string('key')->primary();
            $table->string('owner');
            $table->integer('expiration');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sessions');
        Schema::dropIfExists('cache');
        Schema::dropIfExists('cache_locks');
    }
};
"""
_MIGRATION_ONE = """<?php

use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('fixture_widgets', function (Blueprint $table) {
            $table->id();
            $table->string('name');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('fixture_widgets');
    }
};
"""
_MIGRATION_TWO = """<?php

use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('fixture_notes', function (Blueprint $table) {
            $table->id();
            $table->text('body');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('fixture_notes');
    }
};
"""
_MIGRATION_BROKEN = """<?php

use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Support\\Facades\\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement('this is not valid sql');
    }

    public function down(): void
    {
    }
};
"""
_BROKEN_COMPOSER = "{ this is not json"
_GOOD_BOOTSTRAP = """<?php

use Illuminate\\Foundation\\Application;
use Illuminate\\Foundation\\Configuration\\Exceptions;
use Illuminate\\Foundation\\Configuration\\Middleware;
use Illuminate\\Http\\Request;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        //
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
"""
_HEALTH_RENAMED = """<?php

use Illuminate\\Foundation\\Application;
use Illuminate\\Foundation\\Configuration\\Exceptions;
use Illuminate\\Foundation\\Configuration\\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/health',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        //
    })->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
"""


class LaravelDeployCase(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "sld"
    identity = "sld"
    domain = "site.fixture.test"
    database_engine = "mariadb"

    # -- harness helpers ---------------------------------------------------------------

    def write(self, shell: RemoteShell, path: str, content: str, mode: int = 0o644) -> None:
        result = shell.run(
            f"install -D -m {mode:o} /dev/stdin {shlex.quote(path)}", stdin=content.encode()
        )
        self.assertEqual(result.exit_status, 0, result.stdout)

    def install_acme(self) -> None:
        root = os.environ["BARECTL_FIXTURE_ACME_ROOT"]
        host = os.environ["BARECTL_FIXTURE_ACME_HOST"]
        with open(root, encoding="utf-8") as handle:
            certificate = handle.read()
        original = self.native("cat /etc/caddy/Caddyfile")
        self.addCleanup(
            self.native,
            "printf %s " + shlex.quote(original) + " >/etc/caddy/Caddyfile; systemctl reload caddy",
        )
        self.native(
            "printf %s "
            + shlex.quote(certificate)
            + " >/etc/caddy/pebble.minica.pem; chmod 644 /etc/caddy/pebble.minica.pem"
        )
        # The ACME root is the server's trust anchor for the certificates it serves, the
        # way a real host trusts its CA. Pebble's own HTTPS root trusts the management API;
        # its ACME root, read from that API, is what signs the site certificates Caddy
        # issues, so the body's HTTPS readiness probe can verify them.
        self.native(
            "printf %s "
            + shlex.quote(certificate)
            + " >/usr/local/share/ca-certificates/barectl-pebble-https.crt"
            + " && update-ca-certificates"
        )
        acme_root = self.native(f"curl --silent --show-error --fail https://{host}:15000/roots/0")
        self.assertTrue(acme_root.startswith("-----BEGIN CERTIFICATE-----"), acme_root)
        self.native(
            "printf %s "
            + shlex.quote(acme_root)
            + " >/usr/local/share/ca-certificates/barectl-pebble-acme.crt && update-ca-certificates"
        )
        self.native("printf %s " + shlex.quote(self.caddyfile(host)) + " >/etc/caddy/Caddyfile")
        self.native(
            "/nix/var/nix/profiles/barectl/caddy/bin/caddy validate "
            "--config /etc/caddy/Caddyfile --adapter caddyfile"
        )
        self.native("chown root:root /etc/caddy/Caddyfile; chmod 644 /etc/caddy/Caddyfile")
        self.native("systemctl reload caddy")

    def caddyfile(self, acme_host: str) -> str:
        return (
            "{\n"
            "\tadmin unix//run/caddy/admin.sock|0600\n"
            f"\tacme_ca https://{acme_host}:14000/dir\n"
            "\tacme_ca_root /etc/caddy/pebble.minica.pem\n"
            "\tservers {\n\t\tstrict_sni_host on\n\t}\n"
            "}\n"
            "import sites/*.caddy\n"
            ":80 {\n\trespond 404\n}\n"
        )

    def install_engine(self) -> None:
        from databases import engine as kinds

        with self.shell() as shell:
            self.write(
                shell,
                "/etc/apt/sources.list.d/barectl-fixture.sources",
                mirror.apt_sources(),
            )
            self.write(
                shell,
                "/etc/apt/apt.conf.d/99barectl-fixture",
                'Acquire::By-Hash "no";\nAcquire::Languages "none";\n',
            )
            self.assertEqual(
                shell.run("rm -f /etc/apt/sources.list.d/ubuntu.sources").exit_status, 0
            )
            self.assertEqual(shell.run("apt-get update 2>&1").exit_status, 0)
            apply_change(
                self, kinds.INSTALL, PreparationInputs(self.database_engine, git=True), timeout=180
            )
        self.assertIn("active", self.native(f"systemctl is-active {self.database_name()}.service"))
        self.native("systemctl restart php-fpm@php84.service php-fpm@php85.service")

    def database_name(self) -> str:
        return "postgresql" if self.database_engine == "postgresql" else "mariadb"

    def repository(self) -> str:
        return f"https://{os.environ['BARECTL_FIXTURE_GIT_HOST']}/fixture.git"

    def create(self) -> None:
        from laravel import create

        inputs = PreparationInputs(
            "php84",
            self.identity,
            (self.domain,),
            https=True,
            repository=self.repository(),
            branch="main",
        )
        apply_change(self, create.CREATE_LARAVEL, inputs, timeout=180)

    # -- the lane's Git fixture --------------------------------------------------------

    def push(self, files: dict[str, str], message: str) -> str:
        """Add a commit to the lane's fixture repository and return its full SHA."""
        key = pathlib.Path(os.environ["BARECTL_FIXTURE_GIT_KEY"]).read_bytes()
        host = os.environ["BARECTL_FIXTURE_GIT_HOST"]
        base = "/root/deploy-push"
        key_payload = base64.b64encode(key).decode()
        ssh = (
            "export GIT_SSH_COMMAND='ssh -i /root/deploy-push-key"
            " -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes'"
        )
        lines = [
            "set -eu",
            "umask 077",
            f"printf %s {shlex.quote(key_payload)} | base64 -d > /root/deploy-push-key",
            "chmod 600 /root/deploy-push-key",
            ssh,
            f"rm -rf {base}",
            f"git clone --quiet git@{host}:fixture.git {base}",
            f"cd {base}",
            "git config user.email fixture@barectl.test",
            "git config user.name fixture",
        ]
        # The lane's fixture repository is shared by every scenario on its lane, so each
        # push carries a unique marker: a commit always has a change even when a previous
        # scenario already pushed the same application files.
        files = dict(files)
        files["deploy-marker.txt"] = f"{self.identity}-{message}-{time.time_ns()}\n"
        for name, content in files.items():
            target = shlex.quote(f"{base}/{name}")
            payload = base64.b64encode(content.encode()).decode()
            lines.append(f"mkdir -p $(dirname {target})")
            lines.append(f"printf %s {shlex.quote(payload)} | base64 -d > {target}")
        lines.append(
            f"git add -A && git commit -qm {shlex.quote(message)} "
            "&& git push --quiet origin main && git rev-parse HEAD"
        )
        with self.shell() as shell:
            commit = shell.run("sh -c " + shlex.quote("; ".join(lines)))
        self.assertEqual(commit.exit_status, 0, commit.stdout)
        return commit.stdout.strip().splitlines()[-1]

    # -- driving a reviewed change -----------------------------------------------------

    def review(self, kind: engine.ChangeKind, inputs: PreparationInputs) -> engine.ReviewDraft:
        with self.shell() as shell:
            return kind.review(kind.inspect(shell, inputs), inputs)

    def apply(
        self, kind: engine.ChangeKind, inputs: PreparationInputs, *, timeout: float = 150
    ) -> tuple[engine.ResultLine, str, engine.ReviewDraft]:
        with self.shell() as shell:
            draft = kind.review(kind.inspect(shell, inputs), inputs)
            self.assertTrue(draft.eligible, draft.refusals)
            stored = ChangeReview(
                document=draft.document,
                sites_read=draft.sites_read,
                sites_digest=engine._sites_digest(shell, draft),
            )
            self.assertIsNotNone(draft.uptime_centiseconds)
            unit = native.new_unit_name()
            context = engine.BodyContext(
                unit, draft.boot_id, int(draft.uptime_centiseconds or 0) + 90000
            )
            body = kind.body(draft.document, context)
            path = engine.body_path(unit)
            staged = shell.run(
                shlex.join(engine.stage_command(path, str(draft.document["body_sha256"]))),
                stdin=body.source,
            )
            self.assertEqual(staged.exit_status, 0, staged.stdout)
            payload = engine.payload(kind, stored, context, body, path)
            submitted = shell.run(shlex.join(native.submission(unit, payload, collect=True)))
            self.assertEqual(submitted.exit_status, 0, submitted.stdout)
            end = time.monotonic() + timeout
            line = engine.read_result(shell, unit)
            while line is None and time.monotonic() < end:
                time.sleep(0.1)
                line = engine.read_result(shell, unit)
            if line is None:
                self.fail("No native outcome: " + self.native(f"journalctl -u {unit} -n 40"))
        return line, unit, draft

    def deploy_inputs(self, *, migrations: bool = True) -> PreparationInputs:
        return PreparationInputs("", self.identity, migrations=migrations)

    def assert_succeeded(self, line: engine.ResultLine, unit: str) -> None:
        if line.result_class == "succeeded":
            return
        self.fail(
            "\n".join(
                [
                    f"{line.result_class}/{line.reason}:",
                    self.native(f"journalctl --no-pager -o cat -u {unit}")[-6000:],
                    "services: "
                    + self.native(
                        "systemctl is-active caddy "
                        f"haproxy-site@{self.identity}.service "
                        f"php-fpm-site-php84@{self.identity}.service 2>&1; "
                        f"readlink {self.base()}/current || true"
                    ),
                    "socket: "
                    + self.native(
                        "for p in /up /index.php /; do printf '%s=' \"$p\"; "
                        f"curl -s -o /dev/null -w '%{{http_code}}\\n' --unix-socket "
                        f"/run/haproxy/{self.identity}/http.sock -H 'Host: {self.domain}' "
                        f"http://{self.domain}$p; done"
                    ),
                    "https: "
                    + self.native(
                        "for p in /up /index.php /; do printf '%s=' \"$p\"; "
                        f"curl -s -k -o /dev/null -w '%{{http_code}}\\n' "
                        f"--resolve {self.domain}:443:127.0.0.1 https://{self.domain}$p; done"
                    ),
                    "readiness: " + json.dumps(self.readiness()),
                    "storage logs: " + self.native(f"ls -la {self.base()}/private/storage/logs"),
                    "app log: "
                    + self.native(
                        f"sh -c 'cat {self.base()}/private/storage/logs/*.log 2>/dev/null "
                        "| tail -n 6 || true'"
                    ),
                    "caddy: " + self.native("journalctl --no-pager -u caddy -n 15"),
                ]
            )
        )

    def assert_failed(
        self, line: engine.ResultLine, result_class: str, reason: str, unit: str = ""
    ) -> None:
        if line.result_class == result_class and line.reason == reason:
            return
        self.fail(
            f"{line.result_class}/{line.reason}: expected {result_class}/{reason}\n"
            + (self.native(f"journalctl --no-pager -o cat -u {unit}")[-4000:] if unit else "")
            + "\ncurrent="
            + self.current()
            + "\nbootstrap="
            + self.native(f"grep -n health {self.base()}/current/bootstrap/app.php || true")
            + "\ncache="
            + self.native(f"ls -la {self.base()}/private/cache/")
        )

    # -- reading the server ------------------------------------------------------------

    def base(self) -> str:
        return f"/var/www/{self.identity}"

    def current(self) -> str:
        return self.native(f"readlink {self.base()}/current").strip()

    def current_release(self) -> str:
        target = self.current()
        self.assertTrue(target.startswith("releases/"), target)
        return target[len("releases/") :]

    def https_status(self, path: str = "/") -> int:
        return int(
            self.native(
                "curl --silent --show-error --max-time 20 --insecure --resolve "
                f"{self.domain}:443:127.0.0.1 -o /dev/null -w '%{{http_code}}' "
                f"https://{self.domain}{path}"
            ).strip()
        )

    def https_body(self, path: str = "/") -> str:
        return self.native(
            "curl --silent --show-error --max-time 20 --insecure --resolve "
            f"{self.domain}:443:127.0.0.1 https://{self.domain}{path}"
        )

    def socket_status(self, path: str = "/") -> int:
        return int(
            self.native(
                "curl --silent --show-error --max-time 20 -o /dev/null -w '%{http_code}' "
                f"--unix-socket /run/haproxy/{self.identity}/http.sock "
                f"-H 'Host: {self.domain}' http://{self.domain}{path}"
            ).strip()
        )

    def socket_body(self, path: str = "/") -> str:
        return self.native(
            "curl --silent --show-error --max-time 20 "
            f"--unix-socket /run/haproxy/{self.identity}/http.sock "
            f"-H 'Host: {self.domain}' http://{self.domain}{path}"
        )

    def readiness(self) -> dict[str, int]:
        """The body's own readiness probe over the HAProxy socket and over Caddy's HTTPS."""
        call = "request_readiness(setting({identity!r}, {names!r}, 'php84'){extra})"
        values = {"identity": self.identity, "names": [self.domain]}
        socket = call.format(
            **values, extra=f", socket_path='/run/haproxy/{self.identity}/http.sock'"
        )
        https = call.format(**values, extra="")
        source = (
            f"{self.read_source()}\nprint(canonical({{'socket': {socket}, 'https': {https}}}))\n"
        )
        with self.shell() as shell:
            outcome = run_root(shell, python_command(source, ()))
        self.assertEqual(outcome.exit_status, 0, outcome.stdout[:500])
        value: object = json.loads(outcome.stdout.strip().splitlines()[-1])
        if not isinstance(value, dict):
            self.fail("The readiness probe printed no object: " + outcome.stdout)
        return {str(key): int(str(item)) for key, item in value.items()}

    def read_source(self) -> str:
        from laravel import observation

        return observation.LARAVEL_SOURCE

    def app_key(self) -> str:
        for line in self.native(f"cat {self.base()}/private/laravel.env").splitlines():
            if line.startswith("APP_KEY="):
                return line
        raise AssertionError("The site's environment has no APP_KEY.")

    def _migrations_client(self, statement: str) -> str:
        if self.database_engine == "postgresql":
            return (
                f"runuser -u s{self.identity} -- psql -X -t -A -d s{self.identity} "
                f"-c {shlex.quote(statement)}"
            )
        return (
            f"runuser -u s{self.identity} -- mariadb --no-defaults --protocol=socket "
            f"--socket={MARIADB_SOCKET} s{self.identity} -N -B "
            f"-e {shlex.quote(statement)}"
        )

    def migration_names(self) -> set[str]:
        outcome = self.native(self._migrations_client("SELECT migration FROM migrations"))
        return {line.strip() for line in outcome.splitlines() if line.strip()}

    def migration_count(self, name: str) -> int:
        statement = f"SELECT COUNT(*) FROM migrations WHERE migration = '{name}'"  # noqa: S608
        return int(self.native(self._migrations_client(statement)).strip())

    def assert_gate_open(self) -> None:
        self.assertEqual(self.https_status(), 200, "The site is not open to visitors.")

    # -- native canaries ---------------------------------------------------------------

    def install_execution_canaries(self) -> None:
        """Shadow every program passive discovery must never run with a marker writer."""
        self.native(
            "install -d -m 755 /run/sld-canary && rm -f /run/sld-canary/ran && "
            "for tool in php composer git artisan; do "
            "printf '#!/bin/sh\\necho %s >>/run/sld-canary/ran\\nexit 127\\n' \"$tool\" "
            ">/usr/local/bin/$tool; chmod 755 /usr/local/bin/$tool; done"
        )

    def executed_tools(self) -> list[str]:
        return [
            line.strip()
            for line in self.native(
                "if test -f /run/sld-canary/ran; then cat /run/sld-canary/ran; fi"
            ).splitlines()
            if line.strip()
        ]

    def remove_execution_canaries(self) -> None:
        tools = " ".join(f"/usr/local/bin/{name}" for name in ("php", "composer", "git", "artisan"))
        self.native(f"rm -f {tools}")


@tag(SCENARIO_TAG)
class LaravelDeployMariaDB(LaravelDeployCase):
    """The applied Deploy lifecycle, the migrations switch, Roll back and pruning, and the
    Laravel scheduler's ticks and Run now on the same deployed site (Phase C #265)."""

    prefix = "sld"
    identity = "sld"
    database_engine = "mariadb"
    records: tuple[str, ...] = ("automation-laravel-26.04",)
    schedule_state = "automation-laravel-26.04"

    @override
    @contextmanager
    def shell(self) -> Iterator[RemoteShell]:
        """A plain connection: only the scheduler checkpoint records a transcript.

        Setup applies changes that use the confidential channel, which a recording shell
        refuses by design (ADR 0032).
        """
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            yield connection

    def test_the_applied_lifecycle_on_mariadb(self) -> None:
        from laravel import change, rollback
        from laravel.configuration import ROLLBACK_ACKNOWLEDGEMENT

        self.install_acme()
        self.install_engine()
        self.create()

        first = self.current_release()
        app_key = self.app_key()
        self.assertTrue(first.startswith("bootstrap-"), first)
        # A full passive discovery executes no application code.
        self.install_execution_canaries()
        try:
            with self.shell() as shell:
                from discovery.observations import collect
                from laravel import observation
                from sites import observation as site_observation

                collect(shell, releases=True)
                observation.read(shell)
                site_observation.read(shell, "observed", "")
            self.assertEqual(self.executed_tools(), [], "Passive discovery ran application code.")
        finally:
            self.remove_execution_canaries()

        # -- Deploy 1: the good commit, with a migration -------------------------------
        commit_one = self.push(
            {
                "resources/views/welcome.blade.php": _GOOD_VIEW,
                "bootstrap/app.php": _GOOD_BOOTSTRAP,
                "public/app.css": _GOOD_CSS,
                "database/migrations/2026_10_19_000000_create_sessions_and_cache_tables.php": (
                    _MIGRATION_SESSIONS
                ),
                "database/migrations/2026_10_19_000001_create_fixture_widgets.php": _MIGRATION_ONE,
            },
            "deploy one",
        )
        line, unit, draft = self.apply(change.DEPLOY_SITE, self.deploy_inputs())
        self.assert_succeeded(line, unit)
        # The review states the exact commit; the apply fetched exactly it.
        self.assertEqual(draft.document["commit"], commit_one)
        release_one = f"{commit_one}-{draft.document['token']}"
        self.assertEqual(self.current_release(), release_one)
        self.assertEqual(
            self.native(
                f"runuser -u s{self.identity} -- git -C "
                f"{self.base()}/releases/{release_one} rev-parse HEAD"
            ).strip(),
            commit_one,
        )
        # The build used no dev packages and installed from dist archives.
        vendor = f"{self.base()}/releases/{release_one}/vendor"
        self.assertEqual(
            self.native(
                f"test ! -e {vendor}/phpunit && test ! -e {vendor}/mockery && "
                f"test -d {vendor}/laravel/framework && printf ok"
            ).strip(),
            "ok",
        )
        self.assertEqual(self.native(f"find {vendor} -name .git -maxdepth 3 | head -1"), "")
        # The shared links and the permission classification hold.
        self.assertEqual(
            self.native(
                f"readlink {self.base()}/releases/{release_one}/.env "
                f"{self.base()}/releases/{release_one}/storage "
                f"{self.base()}/releases/{release_one}/bootstrap/cache"
            ).splitlines(),
            [
                f"{self.base()}/private/laravel.env",
                f"{self.base()}/private/storage",
                f"{self.base()}/private/cache",
            ],
        )
        release_dir = f"{self.base()}/releases/{release_one}"
        classification = self.native(
            f"stat -c '%U %G %a %n' {release_dir} {release_dir}/public "
            f"{release_dir}/composer.json {release_dir}/public/index.php "
            f"{release_dir}/public/app.css"
        ).splitlines()
        self.assertEqual(
            classification,
            [
                f"s{self.identity} s{self.identity} 711 {release_dir}",
                f"s{self.identity} caddy 2750 {release_dir}/public",
                f"s{self.identity} s{self.identity} 600 {release_dir}/composer.json",
                f"s{self.identity} s{self.identity} 600 {release_dir}/public/index.php",
                f"s{self.identity} caddy 640 {release_dir}/public/app.css",
            ],
        )
        # The pending migration ran once behind the maintenance gate and is verified.
        self.assertEqual(self.migration_count("2026_10_19_000001_create_fixture_widgets"), 1)
        journal = self.native(f"journalctl --no-pager -o cat -u {unit}")
        self.assertIn("barectl-stage gate", journal)
        self.assertIn("barectl-stage migrations", journal)
        self.assertLess(journal.index("gate"), journal.index("migrations"))
        # Readiness answers 200 over the site's own socket and over Caddy's HTTPS, and the
        # deploy is not gated afterwards.
        self.assertEqual(self.readiness(), {"socket": 200, "https": 200})
        self.assertIn(_GOOD_VIEW.strip(), self.https_body())
        # The file denies the private paths the Laravel convention keeps outside public.
        self.assertEqual(self.https_status("/.env"), 404)
        self.assertEqual(self.https_status("/storage/framework/sessions"), 404)
        # The deploy did not rotate APP_KEY.
        self.assertEqual(self.app_key(), app_key)

        # -- A settings save rebuilds the cached configuration the deploy built --------
        from laravel import settings as environment

        cache = f"{self.base()}/current/bootstrap/cache/config.php"
        self.assertEqual(self.native(f"test -f {cache}; echo $?").strip(), "0")
        apply_change(
            self,
            environment.EDIT_ENVIRONMENT,
            PreparationInputs("", self.identity, settings_changes=(("APP_LOCALE", "set"),)),
            timeout=90,
            secret=json.dumps({"values": {"APP_LOCALE": "de"}}).encode(),
        )
        self.assertIn("APP_LOCALE=de", self.native(f"cat {self.base()}/private/laravel.env"))
        self.assertIn(
            "barectl-stage config",
            self.native(
                "journalctl --since '-2 min' --no-pager -o cat "
                "| grep -F 'barectl-stage config' || true"
            ),
        )
        self.assertEqual(self.https_status(), 200)

        # -- Deploy 2: the migrations switch is off ------------------------------------
        commit_two = self.push(
            {"database/migrations/2026_10_19_000002_create_fixture_notes.php": _MIGRATION_TWO},
            "deploy two",
        )
        line, unit, draft = self.apply(change.DEPLOY_SITE, self.deploy_inputs(migrations=False))
        self.assert_succeeded(line, unit)
        self.assertEqual(self.current_release(), f"{commit_two}-{draft.document['token']}")
        self.assertNotIn("2026_10_19_000002_create_fixture_notes", self.migration_names())
        journal = self.native(f"journalctl --no-pager -o cat -u {unit}")
        self.assertIn("barectl-pending 2026_10_19_000002_create_fixture_notes", journal)
        self.assertNotIn("barectl-stage migrations", journal)

        # -- Roll back to the first release --------------------------------------------
        review_inputs = PreparationInputs("", self.identity, (), release_one)
        draft = self.review(rollback.ROLLBACK_SITE, review_inputs)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["acknowledgement"], ROLLBACK_ACKNOWLEDGEMENT)
        details = cast(list[dict[str, str]], draft.document["details"])
        self.assertIn(
            "Schema, data, storage, settings and queued jobs are unchanged.",
            [entry["value"] for entry in details],
        )
        line, unit, _ = self.apply(rollback.ROLLBACK_SITE, review_inputs)
        self.assert_succeeded(line, unit)
        self.assertEqual(self.current_release(), release_one)
        self.assert_gate_open()

        # -- Deploy 3: pruning names and removes the older releases --------------------
        for index in range(4):
            self.native(
                f"cp -a {self.base()}/releases/{release_one} "
                f"{self.base()}/releases/{index + 1:040x}-{'c' * 16} && "
                f"touch -d '2001-01-01 00:00:0{index}' "
                f"{self.base()}/releases/{index + 1:040x}-{'c' * 16}"
            )
        commit_four = self.push({"README.md": "deploy four\n"}, "deploy four")
        line, unit, draft = self.apply(change.DEPLOY_SITE, self.deploy_inputs())
        self.assert_succeeded(line, unit)
        pruned = [str(name) for name in cast(list[object], draft.document["prune"])]
        self.assertTrue(pruned, "The review named no releases to prune.")
        for name in pruned:
            self.assertEqual(
                self.native(f"test ! -e {self.base()}/releases/{name}; echo $?").strip(), "0"
            )
        self.assertEqual(self.current_release(), f"{commit_four}-{draft.document['token']}")
        self.assert_gate_open()

    # -- the Laravel scheduler (Phase C #265) ----------------------------------------

    def unit_property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value -p {name} {unit}").strip()

    def unit_unix(self, unit: str, name: str) -> int:
        value = self.native(f"systemctl show --value --timestamp=unix -p {name} {unit}").strip()
        return int(value.removeprefix("@") or 0)

    def wait_for_a_tick(self, service: str, after: int, *, timeout: float = 75) -> int:
        """Wait for a completed run that started after ``after``, with no controller open."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            started = self.unit_unix(service, "ExecMainStartTimestamp")
            state = self.unit_property(service, "ActiveState")
            if started > after and state in ("inactive", "failed"):
                return started
            time.sleep(1)
        detail = self.native(f"systemctl status {service} --no-pager -n 20")
        raise AssertionError(f"No scheduler run after the reviewed change: {detail}")

    def _scheduler_checkpoint(self, shell: RemoteShell, inputs: PreparationInputs) -> None:
        from automation import scheduler as scheduler_change
        from automation.status import ScheduleStatus
        from discovery.observations import collect

        observed = collect(shell, releases=True)
        evidence = scheduler_change.inspect(shell, inputs)
        draft = scheduler_change.review(evidence, inputs)
        if not draft.eligible:
            self.fail(f"{draft.refusals} site={evidence.site} laravel={evidence.laravel}")
        self.checkpoint(self.schedule_state, shell)
        row = next(
            item
            for item in observed.automation.value
            if item.identifier == self.identity and item.role == "schedule"
        )
        self.assertEqual(row.status, ScheduleStatus.SUCCEEDED)
        self.assertTrue(row.timer_enabled)
        self.assertTrue(row.timer_active)
        self.assertTrue(draft.no_changes, draft.refusals)
        self.assertEqual(draft.effects, ())

    def test_the_scheduler_ticks_with_the_controller_stopped(self) -> None:
        from automation import scheduler as scheduler_change
        from automation.convention import service_name, timer_name
        from automation.status import ScheduleStatus
        from discovery.observations import collect

        inputs = PreparationInputs("", self.identity, schedule_state="on")
        line, unit, _ = self.apply(scheduler_change.SET_LARAVEL_SCHEDULER, inputs, timeout=90)
        self.assert_succeeded(line, unit)
        timer = timer_name(self.identity, "schedule")
        service = service_name(self.identity, "schedule")
        self.assertEqual(self.unit_property(timer, "ActiveState"), "active")
        self.assertIn("enabled", self.unit_property(timer, "UnitFileState"))
        self.assertEqual(self.unit_property(service, "Type"), "oneshot")
        self.assertIn("1h", self.unit_property(service, "TimeoutStartUSec"))
        self.assertIn(
            f"/var/www/{self.identity}/bin/php "
            f"/var/www/{self.identity}/current/artisan schedule:run",
            self.unit_property(service, "ExecStart"),
        )
        # No Barectl connection stays open: only the harness reads the server container.
        started = self.unit_unix(service, "ExecMainStartTimestamp")
        completed = self.wait_for_a_tick(service, started)
        self.assertGreater(completed, 0)

        state = self.record_state
        if state == self.schedule_state:
            with ssh.connect(self.target()) as connection:
                recording = recorded.RecordingShell(
                    connection, state, secrets=(recorded.SEEDED_SECRET,)
                )
                self._scheduler_checkpoint(recording, inputs)
        else:
            with self.shell() as shell:
                self._scheduler_checkpoint(shell, inputs)

        with self.shell() as shell:
            observed = collect(shell, releases=True)
        row = next(
            item
            for item in observed.automation.value
            if item.identifier == self.identity and item.role == "schedule"
        )
        self.assertEqual(row.status, ScheduleStatus.SUCCEEDED)
        self.assertGreater(row.next_elapse_us, 0)

        # A hand-made crontab entry blocks turning the managed scheduler on.
        cron = "/etc/cron.d/barectl-sld-scheduler-duplicate"
        self.native(
            "printf '%s\\n' "
            + shlex.quote(
                f"* * * * * root /var/www/{self.identity}/bin/php "
                f"/var/www/{self.identity}/current/artisan schedule:run"
            )
            + f" > {cron} && chmod 644 {cron}"
        )
        self.addCleanup(self.native, f"rm -f {cron}")
        blocked = self.review(scheduler_change.SET_LARAVEL_SCHEDULER, inputs)
        self.assertFalse(blocked.eligible)
        self.assertTrue(any("crontab" in refusal for refusal in blocked.refusals), blocked.refusals)

        # Run now starts the installed service once and waits for its result.
        before = self.unit_unix(service, "ExecMainStartTimestamp")
        line, unit, _ = self.apply(
            scheduler_change.SET_LARAVEL_SCHEDULER,
            PreparationInputs("", self.identity, schedule_state="run"),
            timeout=90,
        )
        self.assert_succeeded(line, unit)
        self.assertGreater(self.unit_unix(service, "ExecMainStartTimestamp"), before)

        line, unit, _ = self.apply(
            scheduler_change.SET_LARAVEL_SCHEDULER,
            PreparationInputs("", self.identity, schedule_state="off"),
            timeout=60,
        )
        self.assert_succeeded(line, unit)
        self.assertEqual(self.unit_property(timer, "LoadState"), "not-found")
        self.assertEqual(self.unit_property(service, "LoadState"), "not-found")


@tag(SCENARIO_TAG)
class LaravelDeployOutcomes(LaravelDeployCase):
    """A pre-switch failure with no gate, a failed migration behind the gate, and refusals."""

    prefix = "slf"
    identity = "slf"
    database_engine = "mariadb"

    def put(self, path: str, content: str) -> None:
        self.native(f"printf %s {shlex.quote(content)} > {path} && chmod 644 {path}")

    def refusals(self) -> list[str]:
        from laravel import change, observation

        with self.shell() as shell:
            row = observation.site(observation.read(shell) or {}, self.identity) or {}
        draft = self.review(change.DEPLOY_SITE, self.deploy_inputs())
        if draft.eligible:
            self.fail(
                f"row={row}\n"
                + self.native(
                    f"ls -la {self.base()}/releases 2>&1 | tail -6; "
                    f"stat -c '%U %G %a %F %n' {self.base()}/releases/*/.gitmodules 2>&1"
                )
            )
        return [str(refusal) for refusal in draft.refusals]

    def test_a_build_failure_a_failed_migration_and_the_refusals(self) -> None:
        from laravel import change

        self.install_acme()
        self.install_engine()
        self.create()
        self.push(
            {
                "resources/views/welcome.blade.php": _GOOD_VIEW,
                "bootstrap/app.php": _GOOD_BOOTSTRAP,
                "public/app.css": _GOOD_CSS,
                "database/migrations/2026_10_19_000000_create_sessions_and_cache_tables.php": (
                    _MIGRATION_SESSIONS
                ),
                "database/migrations/2026_10_19_000001_create_fixture_widgets.php": _MIGRATION_ONE,
            },
            "good deploy",
        )
        line, unit, _ = self.apply(change.DEPLOY_SITE, self.deploy_inputs())
        self.assert_succeeded(line, unit)
        current = self.current_release()
        release = f"{self.base()}/releases/{current}"
        self.assertEqual(self.https_status(), 200)

        # -- The repository-shape refusals (#382's deferred criteria) --------------------
        self.native(f"cp -a {release}/.git/config /root/slf-gitconfig")
        self.native(f"cp -a {release}/.git/HEAD /root/slf-head")
        config = self.native(f"cat {release}/.git/config")
        credentialed = "\n".join(
            "url = https://user:token@git/fixture.git"
            if line.strip().startswith("url = ")
            else line
            for line in config.splitlines()
        )
        self.put(f"{release}/.git/config", credentialed)
        self.assertTrue(
            any("could not be read from its release metadata" in r for r in self.refusals())
        )
        self.native(f"cp -a /root/slf-gitconfig {release}/.git/config")

        self.put(f"{release}/.git/HEAD", "ref: refs/heads/-u\n")
        self.assertTrue(any("Git option" in r for r in self.refusals()))
        self.native(f"cp -a /root/slf-head {release}/.git/HEAD")

        self.put(f"{release}/.gitmodules", '[submodule "x"]\n\tpath = x\n\turl = x\n')
        self.assertTrue(any("submodules" in r for r in self.refusals()))
        self.native(f"rm -f {release}/.gitmodules")

        self.put(f"{release}/.gitattributes", "*.bin filter=lfs diff=lfs merge=lfs -text\n")
        self.assertTrue(any("Git LFS" in r for r in self.refusals()))
        self.native(f"rm -f {release}/.gitattributes")

        self.native(f"mkdir -p {release}/.git/hooks")
        self.put(f"{release}/.git/hooks/post-checkout", "#!/bin/sh\ntrue\n")
        self.native(f"chmod 755 {release}/.git/hooks/post-checkout")
        self.assertTrue(any("Git hooks" in r for r in self.refusals()))
        self.native(f"rm -f {release}/.git/hooks/post-checkout")

        # An apply forged without the migration acknowledgement cannot build a body.
        draft = self.review(change.DEPLOY_SITE, self.deploy_inputs())
        forged = dict(draft.document)
        forged.pop("acknowledgement", None)
        with self.assertRaises(ValueError):
            change.body(forged, engine.BodyContext("barectl-apply-" + "0" * 32 + ".service", "", 0))

        # -- A failure before the switch leaves the old release serving with no gate -----
        self.push({"composer.json": _BROKEN_COMPOSER}, "broken composer")
        line, unit, _ = self.apply(change.DEPLOY_SITE, self.deploy_inputs())
        self.assert_failed(line, "partial", "laravel_composer")
        self.assertEqual(self.current_release(), current)
        self.assertEqual(self.https_status(), 200)
        self.assertIn(_GOOD_VIEW.strip(), self.https_body())

        # -- A failed migration keeps the gate and the old release -----------------------
        composer_json = self.native(f"cat {release}/composer.json")
        broken = self.push(
            {
                "composer.json": composer_json,
                "database/migrations/2026_10_19_000003_broken.php": _MIGRATION_BROKEN,
            },
            "broken migration",
        )
        line, unit, draft = self.apply(change.DEPLOY_SITE, self.deploy_inputs())
        self.assert_failed(line, "partial", "laravel_migrations")
        self.assertEqual(self.current_release(), current)
        self.assertEqual(self.https_status(), 503, "The maintenance gate is not up.")
        self.assertIn(_GOOD_VIEW.strip(), self.socket_body())
        self.assertNotIn("2026_10_19_000003_broken", self.migration_names())
        self.assertEqual(
            self.native(f"test -d {self.base()}/releases/{broken}-*/; echo $?").strip(), "0"
        )
        # Nothing is retried and Check what happened reads the original unit.
        with self.shell() as shell:
            journal = engine.read_journal(shell, unit, list(draft.stages))
        self.assertIsNotNone(journal.line)
        self.assertEqual(journal.line.reason if journal.line else "", "laravel_migrations")


@tag(SCENARIO_TAG)
class LaravelDeployBootFailure(LaravelDeployCase):
    """A release whose ``/up`` does not answer is never opened to visitors."""

    prefix = "slb"
    identity = "slb"
    database_engine = "mariadb"

    def test_a_release_whose_readiness_fails_is_never_reached(self) -> None:
        from laravel import change

        self.install_acme()
        self.install_engine()
        self.create()
        self.push(
            {
                "resources/views/welcome.blade.php": _GOOD_VIEW,
                "bootstrap/app.php": _GOOD_BOOTSTRAP,
                "database/migrations/2026_10_19_000000_create_sessions_and_cache_tables.php": (
                    _MIGRATION_SESSIONS
                ),
            },
            "good deploy",
        )
        line, unit, _ = self.apply(change.DEPLOY_SITE, self.deploy_inputs())
        self.assert_succeeded(line, unit)
        good = self.current_release()
        self.assertEqual(self.readiness(), {"socket": 200, "https": 200})

        broken = self.push({"bootstrap/app.php": _HEALTH_RENAMED}, "no up route")
        line, unit, draft = self.apply(change.DEPLOY_SITE, self.deploy_inputs())
        self.assert_failed(line, "partial", "laravel_readiness", unit)
        # Visitors never reach the release whose /up failed; the gate answers 503.
        self.assertEqual(self.https_status(), 503)
        self.assertEqual(self.socket_status("/up"), 404)
        # The run reports exactly which release is current, and the old code is not
        # reactivated automatically; the previous release is retained for a Roll back.
        self.assertEqual(self.current_release(), f"{broken}-{draft.document['token']}")
        self.assertEqual(
            self.native(f"test -d {self.base()}/releases/{good}; echo $?").strip(), "0"
        )
        with self.shell() as shell:
            journal = engine.read_journal(shell, unit, list(draft.stages))
        self.assertIsNotNone(journal.line)
        self.assertEqual(journal.line.reason if journal.line else "", "laravel_readiness")


@tag(SCENARIO_TAG)
class LaravelDeployPostgreSQL(LaravelDeployCase):
    """One Deploy on PostgreSQL (issue #259's ninth criterion)."""

    prefix = "slp"
    identity = "slp"
    database_engine = "postgresql"

    def test_a_deploy_on_postgresql(self) -> None:
        from laravel import change

        self.install_acme()
        self.install_engine()
        self.create()
        app_key = self.app_key()
        commit = self.push(
            {
                "resources/views/welcome.blade.php": _GOOD_VIEW,
                "bootstrap/app.php": _GOOD_BOOTSTRAP,
                "database/migrations/2026_10_19_000000_create_sessions_and_cache_tables.php": (
                    _MIGRATION_SESSIONS
                ),
                "database/migrations/2026_10_19_000001_create_fixture_widgets.php": _MIGRATION_ONE,
            },
            "postgres deploy",
        )
        line, unit, draft = self.apply(change.DEPLOY_SITE, self.deploy_inputs())
        self.assert_succeeded(line, unit)
        self.assertEqual(draft.document["commit"], commit)
        self.assertEqual(self.current_release(), f"{commit}-{draft.document['token']}")
        self.assertEqual(self.readiness(), {"socket": 200, "https": 200})
        self.assertEqual(self.migration_count("2026_10_19_000001_create_fixture_widgets"), 1)
        self.assertIn(_GOOD_VIEW.strip(), self.https_body())
        self.assertEqual(self.app_key(), app_key)
