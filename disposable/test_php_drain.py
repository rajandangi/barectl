import csv
import io
import json
import shlex
import time
from typing import override

from django.test import tag

from operations import engine, native
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from sites.change import CREATE_SITE
from sites.observation import python_command
from sites.php_change import READ_SOURCE, SET_SITE_PHP

from .change_testing import apply_change
from .docker import DockerError
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

PHP = r"""<?php
$directory = '/var/www/s339drain/private/tmp/drain';
$id = $_GET['id'] ?? '';
$mode = $_GET['mode'] ?? '';
$body = file_get_contents('php://input');
if (!preg_match('/^[a-z0-9]+$/', $id)) { http_response_code(400); exit; }
function wait_gate($path) {
    $deadline = microtime(true) + 150;
    do {
        clearstatcache(true, $path);
        if (file_exists($path)) return;
        usleep(10000);
    } while (microtime(true) < $deadline);
    throw new Exception('Fixture gate expired');
}
$record = json_encode(['id'=>$id, 'php'=>PHP_VERSION, 'body'=>$body]);
if ($mode === 'background') {
    header('Content-Type: application/json'); echo $record; fastcgi_finish_request();
    file_put_contents("$directory/$id.entered", 'entered');
    wait_gate("$directory/$id.release");
} elseif ($mode === 'active' || $mode === 'detached') {
    file_put_contents("$directory/$id.entered", 'entered');
    wait_gate("$directory/$id.release");
    if ($mode === 'detached') {
        $php = '/nix/var/nix/profiles/barectl/php'.PHP_MAJOR_VERSION.PHP_MINOR_VERSION.'/bin/php';
        exec('/usr/bin/nohup '.escapeshellarg($php).' '.escapeshellarg("$directory/child.php").
             ' '.escapeshellarg($id).' </dev/null >/dev/null 2>&1 &');
    }
}
file_put_contents("$directory/effects", $record.PHP_EOL, FILE_APPEND|LOCK_EX);
if ($mode !== 'background') { header('Content-Type: application/json'); echo $record; }
"""
CHILD = r"""<?php
$directory = __DIR__; $id = $argv[1];
file_put_contents("$directory/$id.child", (string)getmypid());
$deadline = microtime(true) + 150;
do {
    clearstatcache(true, "$directory/$id.childrelease");
    if (file_exists("$directory/$id.childrelease")) {
        file_put_contents("$directory/effects", json_encode([
            'id'=>$id.'child', 'php'=>PHP_VERSION, 'body'=>'abcde'
        ]).PHP_EOL, FILE_APPEND|LOCK_EX);
        exit(0);
    }
    usleep(10000);
} while (microtime(true) < $deadline);
exit(1);
"""
CLIENT = r"""
import csv, http.client, io, json, pathlib, socket, subprocess, sys, threading, time

ROOT = pathlib.Path("/var/www/s339drain/private/tmp/drain")
PHASE = sys.argv[1]
RESULTS = []
LOCK = threading.Lock()
START = time.monotonic()


def marker(name, value="ready"):
    (ROOT / name).write_text(str(value))


def until(predicate, seconds=130):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.02)
    raise RuntimeError("Fixture gate expired")


def api(command):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(4)
    try:
        client.connect("/run/haproxy/s339drain/admin.sock")
        client.sendall((command + "\n").encode())
        data = b""
        while block := client.recv(65536):
            data += block
        return data.decode()
    finally:
        client.close()


def queue():
    rows = csv.DictReader(io.StringIO(api("show stat").replace("# ", "", 1)))
    for row in rows:
        if row.get("svname") == "BACKEND" and int(row.get("qcur") or 0) >= 1:
            marker("proxy-evidence", json.dumps(row))
            return True
    return False


def kernel_queue():
    output = subprocess.check_output(["ss", "-xlH"], text=True)
    for line in output.splitlines():
        if "/s339drain/php84/app.sock" in line and int(line.split()[2]) >= 1:
            marker("kernel-evidence", line)
            return True
    return False


def request(identifier, mode="", slow=False):
    begin = time.monotonic()
    marker(identifier + ".started", begin)
    try:
        target = "/drain.php?id=" + identifier + "&mode=" + mode
        if slow:
            client = socket.create_connection(("127.0.0.1", 80), timeout=160)
            client.sendall(
                (
                    "POST " + target + " HTTP/1.1\r\nHost: s339drain.example.com\r\n"
                    "Content-Length: 5\r\nExpect: 100-continue\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
                + b"a"
            )
            interim = b""
            while not interim.endswith(b"\r\n\r\n"):
                block = client.recv(1)
                if not block:
                    raise RuntimeError("Slow body connection closed")
                interim += block
            if b" 100 " not in interim:
                raise RuntimeError("No accepted slow body: " + repr(interim))
            marker(identifier + ".accepted")
            until(lambda: (ROOT / (identifier + ".release")).exists())
            client.sendall(b"bcde")
            response = http.client.HTTPResponse(client)
            response.begin()
        else:
            client = http.client.HTTPConnection("127.0.0.1", 80, timeout=160)
            client.request("POST", target, body=b"abcde", headers={"Host": "s339drain.example.com"})
            response = client.getresponse()
        body = response.read().decode()
        result = {
            "id": identifier,
            "status": response.status,
            "body": body,
            "seconds": time.monotonic() - begin,
        }
        client.close()
    except Exception as error:
        result = {"id": identifier, "error": repr(error), "seconds": time.monotonic() - begin}
    with LOCK:
        RESULTS.append(result)


def start(identifier, mode="", slow=False):
    thread = threading.Thread(target=request, args=(identifier, mode, slow))
    thread.start()
    return thread


try:
    threads = []
    if PHASE == "queues":
        request("background", "background")
        until(lambda: (ROOT / "background.entered").exists())
        threads.append(start("active", "active"))
        until(lambda: (ROOT / "active.entered").exists())
        threads.append(start("fpmqueued"))
        until(kernel_queue)
        threads.append(start("proxyqueued"))
        until(queue)
        marker("queue-start", time.monotonic())
        threads.append(start("slow", "", True))
        until(lambda: (ROOT / "slow.accepted").exists())
    elif PHASE == "long":
        for identifier in ("longone", "longtwo"):
            threads.append(start(identifier, "active"))
            until(lambda: (ROOT / (identifier + ".entered")).exists())
        threads.append(start("longqueued"))
        until(queue)
        marker("queue-start", time.monotonic())
    else:
        threads.append(start("detached", "detached"))
        until(lambda: (ROOT / "detached.entered").exists())
    marker("ready", START)
    for thread in threads:
        thread.join(165)
    if any(thread.is_alive() for thread in threads):
        raise RuntimeError("Client remained active")
    marker("responses", json.dumps(RESULTS))
except Exception as error:
    marker("client-error", repr(error))
"""


class PHPDrainCase(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s339drain"
    directory = "/var/www/s339drain/private/tmp/drain"
    initial = "php84"

    @override
    def setUp(self) -> None:
        super().setUp()
        apply_change(
            self,
            CREATE_SITE,
            PreparationInputs(self.initial, self.prefix, (self.prefix + ".example.com",)),
        )
        self.native("install -d -m700 -o ss339drain -g ss339drain " + self.directory)
        self.write("/var/www/s339drain/current/public/drain.php", PHP)
        self.write(self.directory + "/child.php", CHILD)
        self.write("/run/s339drain-client.py", CLIENT)
        self.frozen = self.native(
            "sha256sum /etc/caddy/sites/s339drain.caddy /etc/haproxy/sites/s339drain.cfg "
            "/var/www/s339drain/current/public/drain.php; "
            "systemctl show caddy.service haproxy-site@s339drain.service "
            "-p MainPID -p InvocationID"
        )
        self.addCleanup(self.release_all)

    def write(self, path: str, value: str) -> None:
        self.native("printf %s " + shlex.quote(value) + " > " + shlex.quote(path))

    def release_all(self) -> None:
        self.native(
            "touch "
            + " ".join(
                self.directory + "/" + name
                for name in (
                    "background.release",
                    "active.release",
                    "slow.release",
                    "longone.release",
                    "longtwo.release",
                    "detached.release",
                    "detached.childrelease",
                )
            ),
        )
        self.native("systemctl stop s339drain-clients.service >/dev/null 2>&1 || true")

    def wait_file(self, name: str, *, seconds: float = 40) -> str:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            outcome = self.native(
                "if test -f "
                + self.directory
                + "/client-error; then cat "
                + self.directory
                + "/client-error; elif test -f "
                + self.directory
                + "/"
                + name
                + "; then cat "
                + self.directory
                + "/"
                + name
                + "; else printf pending; fi"
            )
            if outcome != "pending":
                self.assertFalse("Error" in outcome, outcome)
                return outcome
            time.sleep(0.05)
        raise AssertionError("Native fixture did not reach " + name)

    def clients(self, phase: str) -> None:
        self.native(
            "systemd-run --collect --unit=s339drain-clients -- python3 "
            "/run/s339drain-client.py " + phase
        )
        self.wait_file("ready")

    def submit(self, selection: str) -> tuple[str, ChangeReview]:
        inputs = PreparationInputs(selection, self.prefix)
        with self.shell() as shell:
            draft = SET_SITE_PHP.review(SET_SITE_PHP.inspect(shell, inputs), inputs)
            if not draft.eligible:
                details = ""
                if any("unavailable" in refusal for refusal in draft.refusals):
                    try:
                        details = self.native(python_command(READ_SOURCE, (self.prefix,)))
                    except DockerError as error:
                        details = "\n".join(
                            line for line in str(error).splitlines() if line.strip(" ^~")
                        )
                    details += self.native("awk '/s339drain.*app.sock/ {print}' /proc/net/unix")
                self.fail(str(draft.refusals) + "\n" + details[-5000:])
            self.assertFalse(draft.no_changes)
            review = ChangeReview(
                document=draft.document,
                sites_read=draft.sites_read,
                sites_digest=engine._sites_digest(shell, draft),
            )
            context = engine.BodyContext(
                native.new_unit_name(), draft.boot_id, int(draft.uptime_centiseconds or 0) + 90000
            )
            body = SET_SITE_PHP.body(draft.document, context)
            path = engine.body_path(context.unit)
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, str(draft.document["body_sha256"]))),
                    stdin=body.source,
                ).exit_status,
                0,
            )
            payload = engine.payload(SET_SITE_PHP, review, context, body, path)
            self.assertEqual(
                shell.run(
                    shlex.join(native.submission(context.unit, payload, collect=True))
                ).exit_status,
                0,
            )
        return context.unit, review

    def result(self, unit: str, expected: str) -> None:
        deadline = time.monotonic() + 75
        with self.shell() as shell:
            while time.monotonic() < deadline:
                result = engine.read_result(shell, unit)
                if result is not None:
                    self.assertEqual(result.result_class, expected, result.reason)
                    return
                time.sleep(0.1)
        self.fail(self.native("journalctl --no-pager -u " + unit + " -n30"))

    def api(self, command: str) -> str:
        script = (
            "import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(3); "
            "s.connect('/run/haproxy/s339drain/admin.sock'); "
            "s.sendall("
            + repr((command + "\n").encode())
            + "); data=b''\n"
            + "while part:=s.recv(65536): data+=part\n"
            + "print(data.decode())"
        )
        return self.native("python3 -c " + shlex.quote(script))

    def proxy_queue(self) -> int:
        rows = csv.DictReader(io.StringIO(self.api("show stat").replace("# ", "", 1)))
        return int(next(row["qcur"] for row in rows if row["svname"] == "BACKEND"))

    def admission(self, target: str) -> None:
        source = "php85" if target == "php84" else "php84"
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            raw = self.api("show servers state")
            rows = [line.split() for line in raw.splitlines() if line and not line.startswith("#")]
            states = {row[3]: row[6] for row in rows if len(row) >= 7}
            if states.get(target) == "4" and states.get(source) == "5":
                return
            time.sleep(0.05)
        self.fail("Native admission did not select " + target)

    def retain(self, source: str) -> None:
        self.assertEqual(
            self.native(
                "systemctl is-active php-fpm-site-" + source + "@s339drain.service"
            ).strip(),
            "active",
        )

    def release(self, *names: str) -> None:
        self.native("touch " + " ".join(shlex.quote(self.directory + "/" + name) for name in names))

    def responses(self, expected: dict[str, str]) -> list[dict[str, object]]:
        rows: object = json.loads(self.wait_file("responses", seconds=50))
        self.assertIsInstance(rows, list)
        if not isinstance(rows, list):
            self.fail("Responses are not a list.")
        self.assertEqual(len(rows), len(expected), rows)
        for row in rows:
            self.assertIsInstance(row, dict)
            self.assertEqual(row.get("status"), 200, row)
            body = json.loads(row["body"])
            self.assertEqual(body["body"], "abcde")
            self.assertTrue(body["php"].startswith(expected[body["id"]] + "."), body)
        return rows

    def effects(self, identifiers: set[str]) -> None:
        raw = self.native("cat " + self.directory + "/effects")
        rows = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual({row["id"] for row in rows}, identifiers, rows)
        self.assertEqual(len(rows), len(identifiers), rows)
        self.assertTrue(all(row["body"] == "abcde" for row in rows), rows)

    def status(self, entry: str) -> list[dict[str, object]]:
        command = shlex.join(
            [
                "env",
                "-i",
                "SCRIPT_NAME=/status",
                "SCRIPT_FILENAME=/status",
                "REQUEST_METHOD=GET",
                "QUERY_STRING=json&full",
                "/nix/var/nix/profiles/barectl/fcgi/bin/cgi-fcgi",
                "-bind",
                "-connect",
                f"/run/php-fpm/sites/s339drain/{entry}/status/listen.sock",
            ]
        )
        response = self.native(command).replace("\r\n", "\n")
        value: object = json.loads(response.partition("\n\n")[2])
        if not isinstance(value, dict) or not isinstance(value.get("processes"), list):
            raise AssertionError("No independent full FPM status.")
        self.assertEqual(value.get("pool"), self.prefix)
        self.assertEqual(value.get("total processes"), 2)
        master = self.native(
            f"systemctl show --value -p MainPID php-fpm-site-{entry}@s339drain.service"
        ).strip()
        children = self.native("ps --ppid " + master + " -o pid=,args=")
        app_pids = {
            int(line.split()[0])
            for line in children.splitlines()
            if line.split(maxsplit=1)[1] == "php-fpm: pool s339drain"
        }
        self.assertEqual({process["pid"] for process in value["processes"]}, app_pids)
        self.assertEqual(len(app_pids), 2)
        return [
            {"pid": process["pid"], "state": process["state"]} for process in value["processes"]
        ]

    def unchanged(self) -> None:
        self.assertEqual(
            self.native(
                "sha256sum /etc/caddy/sites/s339drain.caddy /etc/haproxy/sites/s339drain.cfg "
                "/var/www/s339drain/current/public/drain.php; "
                "systemctl show caddy.service haproxy-site@s339drain.service "
                "-p MainPID -p InvocationID"
            ),
            self.frozen,
        )


@tag(SCENARIO_TAG)
class SitePHPQueuedDrain(PHPDrainCase):
    def test_queued_slow_body_and_post_response_work_survive_partial_then_finish(self) -> None:
        self.clients("queues")
        self.assertIn("/php84/app.sock", self.wait_file("kernel-evidence"))
        self.assertGreaterEqual(int(json.loads(self.wait_file("proxy-evidence"))["qcur"]), 1)
        before = self.status("php84")
        self.assertTrue(any(process["state"] == "Finishing" for process in before))
        unit, _ = self.submit("php85")
        self.admission("php85")
        self.release("active.release", "slow.release")
        self.result(unit, "partial")
        self.retain("php84")
        after = self.status("php84")
        self.assertTrue(any(process["state"] == "Finishing" for process in after))
        self.assertEqual(
            {process["pid"] for process in before},
            {process["pid"] for process in after},
        )
        self.assertNotIn('"id":"background"', self.native("cat " + self.directory + "/effects"))
        self.release("background.release")
        self.responses(
            {
                "background": "8.4",
                "active": "8.4",
                "fpmqueued": "8.4",
                "proxyqueued": "8.5",
                "slow": "8.5",
            }
        )
        apply_change(self, SET_SITE_PHP, PreparationInputs("php85", self.prefix))
        self.effects({"background", "active", "fpmqueued", "proxyqueued", "slow"})
        self.unchanged()


@tag(SCENARIO_TAG)
class SitePHPLongDrain(PHPDrainCase):
    initial = "php85"

    def test_request_over_thirty_seconds_and_queue_over_five_seconds_are_not_cut_off(self) -> None:
        self.clients("long")
        queued = float(self.wait_file("queue-start"))
        self.wait_elapsed(queued, 5.2)
        self.assertGreaterEqual(self.proxy_queue(), 1)
        unit, _ = self.submit("php84")
        self.admission("php84")
        self.result(unit, "partial")
        self.retain("php85")
        started = max(
            float(self.wait_file("longone.started")), float(self.wait_file("longtwo.started"))
        )
        self.wait_elapsed(started, 31)
        self.release("longone.release", "longtwo.release")
        rows = self.responses({"longone": "8.5", "longtwo": "8.5", "longqueued": "8.4"})
        self.assertTrue(
            all(
                float(str(row["seconds"])) > 30
                for row in rows
                if row["id"] in ("longone", "longtwo")
            ),
            rows,
        )
        apply_change(self, SET_SITE_PHP, PreparationInputs("php84", self.prefix))
        self.effects({"longone", "longtwo", "longqueued"})
        self.unchanged()

    def wait_elapsed(self, start: float, seconds: float) -> None:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            elapsed = float(
                self.native(
                    "python3 -c " + shlex.quote(f"import time; print(time.monotonic()-{start!r})")
                )
            )
            if elapsed >= seconds:
                return
            time.sleep(0.05)
        self.fail("Fixture elapsed-time boundary was not reached.")


@tag(SCENARIO_TAG)
class SitePHPDetachedDrain(PHPDrainCase):
    def test_detached_application_child_preserves_source_until_fresh_finish_review(self) -> None:
        self.clients("detached")
        unit, _ = self.submit("php85")
        self.admission("php85")
        self.release("detached.release")
        child = self.wait_file("detached.child")
        self.assertTrue(child.isdecimal(), child)
        master = self.native(
            "systemctl show --value -p MainPID php-fpm-site-php84@s339drain.service"
        ).strip()
        self.assertEqual(
            self.native("cat /proc/" + child + "/cgroup"),
            self.native("cat /proc/" + master + "/cgroup"),
        )
        self.result(unit, "partial")
        self.retain("php84")
        self.responses({"detached": "8.4"})
        observed = self.status("php84")
        self.assertTrue(all(process["state"] == "Idle" for process in observed))
        self.release("detached.childrelease")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if (
                self.native("test -e /proc/" + child + "/stat && printf live || printf gone")
                == "gone"
            ):
                break
            time.sleep(0.05)
        else:
            self.fail("Detached fixture child did not exit normally.")
        apply_change(self, SET_SITE_PHP, PreparationInputs("php85", self.prefix))
        self.effects({"detached", "detachedchild"})
        self.unchanged()
