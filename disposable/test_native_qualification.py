"""Native qualification items of Phase A (docs/phase-a-qualification.md#qualification-items)."""

import json
import re
import shlex
import time
from pathlib import Path
from typing import ClassVar, override

from django.conf import settings as django_settings
from django.test import tag

from operations.inputs import PreparationInputs
from sites.change import CREATE_SITE

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

PROFILES = "/nix/var/nix/profiles"
NIX = PROFILES + "/default/bin"

READER = r"""
import os, pathlib, sys
profile, stop, report, *allowed = sys.argv[1:]
pathlib.Path(report + ".ready").touch()
seen = {}
missing_after = 0
appeared = False
reads = 0
while not os.path.exists(stop):
    reads += 1
    try:
        target = os.path.realpath(profile, strict=True)
    except FileNotFoundError:
        if appeared:
            missing_after += 1
        continue
    appeared = True
    seen[target] = seen.get(target, 0) + 1
    if target in allowed:
        listing = os.listdir(target + "/bin")
        if not listing:
            seen["empty:" + target] = seen.get("empty:" + target, 0) + 1
pathlib.Path(report + ".part").write_text(f"{reads}\n{missing_after}\n" + "\n".join(sorted(seen)))
os.replace(report + ".part", report)
"""


@tag(SCENARIO_TAG)
class ProfileSwitchAtomicity(ScenarioTestCase):
    """`nix-env --set` as the add-runtime body runs it, with ADR 0028's nix.conf."""

    layer = "L1"
    exclusive = True
    prefix = "q341profile"

    def test_set_creates_and_switches_generations_atomically_and_builds_nothing(self) -> None:
        profile = f"{PROFILES}/q341profile/probe"
        php84, php85 = (
            self.native(f"readlink -f {PROFILES}/barectl/{entry}").strip()
            for entry in ("php84", "php85")
        )
        self.assertNotEqual(php84, php85)
        self.assertEqual(
            self.native(
                f"{NIX}/nix --extra-experimental-features nix-command config show max-jobs"
            ).strip(),
            "0",
        )
        self.native(f"install -d -m 755 {PROFILES}/q341profile")
        self.addCleanup(self.native, f"rm -rf {PROFILES}/q341profile /run/q341profile-*")
        self.native("printf %s " + shlex.quote(READER) + " >/run/q341profile-reader.py")
        store = self.native("ls /nix/store | sort | sha256sum")
        self.native(
            "systemd-run --collect --unit=q341profile-reader -- python3 "
            + shlex.join(
                [
                    "/run/q341profile-reader.py",
                    profile,
                    "/run/q341profile-stop",
                    "/run/q341profile-report",
                    php84,
                    php85,
                ]
            )
        )
        self.wait_file("/run/q341profile-report.ready")
        switches = 40
        output = self.native(
            f"{NIX}/nix-env --profile {profile} --set {php84} 2>&1; "
            f"for i in $(seq {switches // 2}); do "
            f"{NIX}/nix-env --profile {profile} --set {php85} 2>&1; "
            f"{NIX}/nix-env --profile {profile} --set {php84} 2>&1; done",
            timeout=120,
        )
        self.native("touch /run/q341profile-stop")
        reads, missing, *seen = self.wait_file("/run/q341profile-report").splitlines()
        self.assertNotRegex(output, r"(?i)build|download|copying")
        self.assertEqual(self.native("ls /nix/store | sort | sha256sum"), store)
        self.assertEqual(int(missing), 0)
        self.assertEqual(seen, sorted([php84, php85]))
        self.assertGreater(int(reads), switches * 10)
        generations = self.native(f"{NIX}/nix-env --profile {profile} --list-generations")
        self.assertEqual(len(generations.splitlines()), switches + 1, generations)
        self.assertEqual(self.native(f"readlink -f {profile}").strip(), php84)
        self.assertEqual(
            self.native(f"ls {PROFILES}/q341profile").split(),
            sorted(["probe", *(f"probe-{n}-link" for n in range(1, switches + 2))]),
        )

    def wait_file(self, path: str) -> str:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.native(f"test -e {path} && echo yes || true").strip():
                return self.native(f"cat {path}").strip()
            time.sleep(0.05)
        raise AssertionError(self.native("journalctl -u q341profile-reader -n 20 --no-pager"))


SLOW = r"""<?php
$directory = '/var/www/q341restart/private/tmp/gate';
$id = $_GET['id'] ?? '';
if (!preg_match('/^[a-z0-9]+$/', $id)) { http_response_code(400); exit; }
file_put_contents("$directory/$id.entered", (string)getmypid());
$deadline = microtime(true) + 120;
do {
    clearstatcache(true, "$directory/$id.release");
    if (file_exists("$directory/$id.release")) break;
    usleep(10000);
} while (microtime(true) < $deadline);
file_put_contents("$directory/effects", $id.PHP_EOL, FILE_APPEND|LOCK_EX);
echo 'released:'.$id;
"""

CLIENT = r"""
import http.client, json, pathlib, sys, threading, time

ROOT = pathlib.Path("/var/www/q341restart/private/tmp/gate")
REPORT = pathlib.Path(sys.argv[1])
HOST = "q341restart.example.com"
results = {"slow": None, "loop": []}


def get(target):
    begin = time.monotonic()
    try:
        client = http.client.HTTPConnection("127.0.0.1", 80, timeout=150)
        client.request("GET", target, headers={"Host": HOST})
        response = client.getresponse()
        body = response.read().decode()
        client.close()
        return {"start": begin, "end": time.monotonic(), "status": response.status, "body": body}
    except Exception as error:
        return {"start": begin, "end": time.monotonic(), "error": repr(error)}


def slow():
    results["slow"] = get("/slow.php?id=inflight")


thread = threading.Thread(target=slow)
thread.start()
while not (ROOT / "inflight.entered").exists():
    time.sleep(0.01)
(ROOT / "ready").write_text("ready")
while not (ROOT / "stop").exists():
    results["loop"].append(get("/index.php"))
    time.sleep(0.02)
thread.join(150)
REPORT.write_text(json.dumps(results))
"""


@tag(SCENARIO_TAG)
class SitePHPMasterRestart(ScenarioTestCase):
    """A site master's restart and a runtime master's pool reload with requests running."""

    layer = "L1"
    exclusive = True
    prefix = "q341restart"
    gate = "/var/www/q341restart/private/tmp/gate"
    created: ClassVar[bool] = False

    @override
    def setUp(self) -> None:
        super().setUp()
        if not SitePHPMasterRestart.created:
            apply_change(
                self,
                CREATE_SITE,
                PreparationInputs("php84", self.prefix, (self.prefix + ".example.com",)),
            )
            SitePHPMasterRestart.created = True
            self.native(
                "printf %s "
                + shlex.quote("<?php echo 'ok:'.PHP_VERSION;")
                + " >/var/www/q341restart/current/public/index.php; printf %s "
                + shlex.quote(SLOW)
                + " >/var/www/q341restart/current/public/slow.php; printf %s "
                + shlex.quote(CLIENT)
                + " >/run/q341restart-client.py"
            )
        self.native(
            f"rm -rf {self.gate} /run/q341restart-report; "
            f"install -d -m 700 -o sq341restart -g sq341restart {self.gate}"
        )
        self.addCleanup(self.native, f"touch {self.gate}/inflight.release {self.gate}/stop")

    def now(self) -> float:
        return float(self.native("python3 -c 'import time; print(time.monotonic())'"))

    def wait(self, command: str, seconds: float = 60) -> str:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            output = self.native(command + " 2>/dev/null || true").strip()
            if output:
                return output
            time.sleep(0.05)
        raise AssertionError("Timed out: " + command)

    def start_client(self) -> None:
        self.native(
            "systemd-run --collect --unit=q341restart-client -- python3 "
            "/run/q341restart-client.py /run/q341restart-report"
        )
        self.wait(f"cat {self.gate}/ready")

    def finish_client(self) -> dict[str, object]:
        time.sleep(1)
        self.native(f"touch {self.gate}/stop")
        report: object = json.loads(self.wait("cat /run/q341restart-report"))
        if not isinstance(report, dict):
            raise AssertionError(report)
        return report

    def test_restart_waits_for_the_running_request_and_refuses_only_while_restarting(
        self,
    ) -> None:
        unit = "php-fpm-site-php84@q341restart.service"
        before = self.native(f"systemctl show --value -p MainPID {unit}").strip()
        self.start_client()
        begin = self.now()
        self.native(f"systemctl restart --no-block {unit}")
        time.sleep(2)
        self.assertEqual(self.native(f"cat {self.gate}/effects 2>/dev/null || true"), "")
        self.assertEqual(
            self.native(f"systemctl show --value -p ActiveState {unit}").strip(), "deactivating"
        )
        self.native(f"touch {self.gate}/inflight.release")
        self.wait(
            f"[ $(systemctl show --value -p ActiveState {unit}) = active ] && "
            f"[ $(systemctl show --value -p MainPID {unit}) != {before} ] && echo up"
        )
        end = self.now()
        report = self.finish_client()
        slow = report["slow"]
        self.assertIsInstance(slow, dict)
        self.assertEqual(slow, {**slow, "status": 200, "body": "released:inflight"})  # type: ignore[dict-item]
        self.assertEqual(self.native(f"cat {self.gate}/effects").split(), ["inflight"])
        loop = report["loop"]
        if not isinstance(loop, list):
            raise AssertionError(report)
        refused = [row for row in loop if row.get("status") != 200]
        served_after = [row for row in loop if row["start"] > end]
        self.assertTrue(served_after)
        self.assertTrue(all(row.get("status") == 200 for row in served_after), served_after)
        self.assertTrue(all(begin <= row["start"] <= end for row in refused), refused)
        self.assertTrue(all(row.get("status") in (502, 503) for row in refused), refused)
        window = (
            (max(row["end"] for row in refused) - min(row["start"] for row in refused))
            if refused
            else 0.0
        )
        print(  # noqa: T201 - measured for docs/phase-a-qualification.md
            f"\nrestart: {end - begin:.2f} s, {len(loop)} requests, {len(refused)} refused, "
            f"refusal window {window:.2f} s"
        )

    def test_runtime_pool_reload_leaves_site_requests_and_masters_untouched(self) -> None:
        site = "php-fpm-site-php84@q341restart.service"
        identity = self.native(f"systemctl show -p MainPID -p InvocationID {site}")
        runtime = self.native("systemctl show -p MainPID -p InvocationID php-fpm@php84.service")
        self.start_client()
        self.native("systemctl reload php-fpm@php84.service")
        time.sleep(1)
        self.native(f"touch {self.gate}/inflight.release")
        report = self.finish_client()
        slow = report["slow"]
        self.assertIsInstance(slow, dict)
        self.assertEqual(slow, {**slow, "status": 200, "body": "released:inflight"})  # type: ignore[dict-item]
        loop = report["loop"]
        if not isinstance(loop, list):
            raise AssertionError(report)
        self.assertTrue(all(row.get("status") == 200 for row in loop), loop)
        self.assertEqual(self.native(f"systemctl show -p MainPID -p InvocationID {site}"), identity)
        self.assertEqual(
            self.native("systemctl show -p MainPID -p InvocationID php-fpm@php84.service"),
            runtime,
        )

    def test_a_runtime_master_reload_ends_its_own_running_request(self) -> None:
        self.native(
            "install -d -m 755 /run/q341restart-diag; "
            "install -d -m 700 -o php-probe -g php-probe /run/q341restart-diag/mark; printf %s "
            + shlex.quote(
                "<?php file_put_contents('/run/q341restart-diag/mark/started', 'started'); "
                "sleep(3); echo 'diagnostic-done';"
            )
            + " >/run/q341restart-diag/slow.php; chmod 644 /run/q341restart-diag/slow.php"
        )
        self.addCleanup(self.native, "rm -rf /run/q341restart-diag")
        request = shlex.join(
            [
                "env",
                "-i",
                "SCRIPT_NAME=/slow.php",
                "SCRIPT_FILENAME=/run/q341restart-diag/slow.php",
                "REQUEST_METHOD=GET",
                f"{PROFILES}/barectl/fcgi/bin/cgi-fcgi",
                "-bind",
                "-connect",
                "/run/php-fpm/php84/diagnostic.sock",
            ]
        )
        outcomes = []
        for reload in (False, True, True, True, True):
            self.native(
                "rm -f /run/q341restart-diag/out /run/q341restart-diag/mark/started; "
                "systemd-run --collect --unit=q341restart-diag "
                "-p StandardOutput=file:/run/q341restart-diag/out -- " + request
            )
            self.wait("cat /run/q341restart-diag/mark/started", seconds=10)
            if reload:
                self.native("systemctl reload php-fpm@php84.service")
            self.wait(
                "systemctl is-active --quiet q341restart-diag.service || echo done", seconds=10
            )
            outcomes.append("diagnostic-done" in self.native("cat /run/q341restart-diag/out"))
        print(  # noqa: T201 - measured for docs/phase-a-qualification.md
            f"\nreload: {outcomes[1:].count(False)} of 4 running requests ended"
        )
        self.assertTrue(outcomes[0])
        self.assertIn(False, outcomes[1:])
        self.assertIn(
            "reloading: execvp",
            self.native("journalctl -u php-fpm@php84 -n 8 --no-pager -o cat"),
        )

    def test_recovery_guide_commands_work_as_written(self) -> None:
        self.native(
            "printf %s "
            + shlex.quote("<?php error_log('q341 recovery'); echo 'ok';")
            + " >/var/www/q341restart/current/public/warn.php"
        )
        self.assertEqual(
            self.native(
                "curl --fail --silent -H 'Host: q341restart.example.com' http://127.0.0.1/warn.php"
            ),
            "ok",
        )
        commands = [
            *recovery_commands("Inspecting"),
            "journalctl -u php-fpm-site-php84@<id> --no-pager",
            "journalctl -t haproxy-site-<id> --no-pager",
            "journalctl -u caddy --no-pager",
            "tail -n 5 /var/www/<id>/logs/access.json",
            *recovery_commands("Restarting"),
        ]
        failures = []
        outputs = {}
        for command in commands:
            line = command.replace("<id>", self.prefix)
            output = self.native(f"{{ {line}; }} 2>&1; printf '\\nexit=%s' $?", timeout=60)
            outputs[command] = output
            if not output.endswith("exit=0"):
                failures.append(f"{line}\n{output[-1500:]}")
        self.assertEqual(failures, [])
        self.assertIn("php84", outputs["ls -l /nix/var/nix/profiles/barectl/"])
        self.assertIn("q341 recovery", outputs["tail -n 50 /var/www/<id>/logs/php-error.log"])
        self.assertIn("warn.php", outputs["tail -n 5 /var/www/<id>/logs/access.json"])
        self.wait(
            "systemctl is-active caddy php-fpm-site-php84@q341restart "
            "haproxy-site@q341restart php-fpm@php84 nix-daemon | grep -qvx active || echo all"
        )
        self.assertEqual(
            self.native(
                "curl --fail --silent -H 'Host: q341restart.example.com' http://127.0.0.1/index.php"
            ),
            "ok:"
            + self.native("/nix/var/nix/profiles/barectl/php84/bin/php -r 'echo PHP_VERSION;'"),
        )


def recovery_commands(section: str) -> list[str]:
    text = (Path(django_settings.BASE_DIR) / "docs" / "recovery.md").read_text()
    body = text.split(f"## {section}\n", 1)[1].split("\n## ", 1)[0]
    block = re.search(r"```sh\n(.*?)```", body, re.DOTALL)
    if block is None:
        raise AssertionError(section)
    return [line.split("  #", 1)[0].strip() for line in block.group(1).splitlines() if line.strip()]
