"""S5 reconstruction: two fresh controllers rebuild the same three-site server alike."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TypedDict, cast

from django.test import tag

from bootstrap.standing import Standing
from discovery.models import SiteState
from operations.inputs import PreparationInputs

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

PREFIX = "s5"
SITES = (("s5alpha", "php84"), ("s5beta", "php84"), ("s5gamma", "php85"))
DEFAULT_PHP = "php85"
NODE = "nodejs_24"

# Every review a reconstructing controller repeats; each must propose no changes.
REVIEWS: tuple[tuple[str, dict[str, object]], ...] = (
    ("host_foundation", {"version": 1}),
    ("set_default_php", {"version": 1, "selection": DEFAULT_PHP}),
    ("set_default_node", {"version": 1, "selection": NODE}),
    ("set_site_node", {"version": 1, "selection": NODE, "identifier": SITES[0][0]}),
    *(
        (
            "create_http_site",
            {
                "version": 1,
                "selection": runtime,
                "identifier": identifier,
                "names": [identifier + ".example.com"],
            },
        )
        for identifier, runtime in SITES
    ),
    *(
        ("set_site_php", {"version": 1, "selection": runtime, "identifier": identifier})
        for identifier, runtime in SITES
    ),
)

# One review of each kind and each site shape keeps the recording within the scenario limit.
RECORDED_REVIEWS = tuple(REVIEWS[index] for index in (0, 1, 2, 3, 4, 6, 7))

_CONTROLLER = """
import dataclasses
import enum
import json
import os

import django
from config import settings

settings.DATABASES["default"]["NAME"] = os.environ["S5_DATABASE"]
os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
django.setup()

from django.contrib.auth.models import User
from django.core.management import call_command
from discovery.fakes import run_worker
from discovery.models import DiscoveryAttempt
from discovery.snapshot import current_snapshot
from operations.services import request_prepare
from servers.connections import saved_alias
from servers.credentials import load_key
from servers.models import Server
from servers.registration import save_server
from servers.trust import confirm_host, pending_challenge

call_command("migrate", verbosity=0, interactive=False)
user = User.objects.create_superuser("operator")
address, port, username = "127.0.0.1", int(os.environ["S5_PORT"]), os.environ["S5_USER"]
_, credential = load_key("controller")
server = Server(
    name="Reconstructed",
    ssh_alias=saved_alias(address, username, port),
    connection_mode="keyfile",
    address=address,
    port=port,
    username=username,
    credential_reference=credential.reference,
    credential_public_key=credential.public_key,
    credential_file_identity=credential.file_identity,
)
save_server(server, user=user)
run_worker()
challenge = pending_challenge(server)
if challenge is None:
    raise AssertionError("A fresh controller trusted the host without a challenge.")
confirm_host(
    server,
    attempt_id=challenge.pk,
    revision=server.connection_revision,
    fingerprint=os.environ["S5_FINGERPRINT"],
    user=user,
)
run_worker()
latest = DiscoveryAttempt.objects.filter(server=server).first()
snapshot = current_snapshot(server)
if snapshot is None:
    raise AssertionError("No discovery after confirmation: " + str(latest and latest.failure))


def plain(value):
    if isinstance(value, enum.Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if hasattr(value, "_asdict"):
        return {k: plain(v) for k, v in value._asdict().items()}
    if isinstance(value, (tuple, list)):
        return [plain(item) for item in value]
    return value


collected = plain(snapshot.collected)
# Free space and memory move between two reads; everything else is the server's state.
for volatile in ("memory_bytes", "filesystem"):
    collected.pop(volatile)
collected["standing"]["evidence"] = [
    row for row in collected["standing"]["evidence"]
    if not row[0].startswith(("Free disk", "Available memory"))
]
reviews = []
for slug, inputs in json.loads(os.environ["S5_REVIEWS"]):
    preparation = request_prepare(server, user, slug, inputs=inputs)
    if preparation is None:
        raise AssertionError("Preparation was not queued.")
    run_worker()
    preparation.refresh_from_db()
    review = preparation.review
    if review is None:
        raise AssertionError(slug + " prepared no review: " + preparation.failure)
    reviews.append({
        "slug": slug,
        "inputs": inputs,
        "eligible": review.eligible,
        "no_changes": review.no_changes,
        "effects": review.effects,
    })
sites = collected["sites"]["value"]
print(json.dumps({
    "summary": {
        "standing": collected["standing"]["standing"],
        "sites": {
            site["identifier"]: [site["state"], site["php_version"], site["node_runtime"]]
            for site in sites
        },
        "accounts": sorted({site["account"]["uid"] for site in sites}),
        "default_php": collected["runtime_defaults"]["php"],
        "default_node": collected["runtime_defaults"]["node"],
    },
    "challenge": [challenge.challenge_key_type, challenge.challenge_fingerprint],
    "observed": collected,
    "reviews": reviews,
}, default=str))
"""


class _Review(TypedDict):
    slug: str
    no_changes: bool


class _Summary(TypedDict):
    standing: str
    sites: dict[str, list[str]]
    accounts: list[int]
    default_php: str
    default_node: str


class _Report(TypedDict):
    challenge: list[str]
    summary: _Summary
    observed: dict[str, object]
    reviews: list[_Review]


@tag(SCENARIO_TAG)
class FreshControllerReconstruction(ScenarioTestCase):
    """Two controllers with empty databases reconstruct one three-site server identically."""

    layer = "L1"
    exclusive = True
    prefix = PREFIX
    records: tuple[str, ...] = ("reconstruction-26.04",)

    def test_two_fresh_controllers_reconstruct_the_same_server_and_propose_nothing(self) -> None:
        self.build()
        if self.record_state == "reconstruction-26.04":
            # Recording replays every review over one connection, which leaves no time
            # within the scenario limit for the two controllers.
            self.checkpoint_reviews()
            return
        fingerprint = self.native(
            "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2"
        ).strip()
        # The repeated reviews are split between the controllers to stay within the
        # scenario limit; each controller still reconstructs the whole server.
        shares = {"a": REVIEWS[0::2], "b": REVIEWS[1::2]}
        with tempfile.TemporaryDirectory(prefix="barectl-s5-") as directory:
            root = Path(directory)
            processes = {
                name: self.start(root / name, fingerprint, reviews)
                for name, reviews in shares.items()
            }
            results = {name: self.finish(process) for name, process in processes.items()}
        for name, result in results.items():
            with self.subTest(controller=name):
                self.assertEqual(result["challenge"], ["ssh-ed25519", fingerprint])
                self.assertEqual(len(result["reviews"]), len(shares[name]))
                for review in result["reviews"]:
                    self.assertTrue(review["no_changes"], review)
        self.maxDiff = None
        self.assertEqual(results["a"]["observed"], results["b"]["observed"])
        summary = results["a"]["summary"]
        self.assertEqual(summary["standing"], Standing.TARGET_STACK)
        self.assertEqual(
            summary["sites"],
            {
                identifier: [SiteState.MANAGED, runtime, NODE if identifier == "s5alpha" else ""]
                for identifier, runtime in SITES
            },
        )
        self.assertEqual(summary["default_php"], DEFAULT_PHP)
        self.assertEqual(summary["default_node"], NODE)
        self.assertEqual(len(summary["accounts"]), 3)

    def build(self) -> None:
        """Alpha through the change engine; beta and gamma by the convention's own operations.

        Making two sites outside the engine keeps the scenario within its limit; S9
        proves a convention site made that way is discovered and managed alike.
        """
        from runtimes.change import ADD_RUNTIME
        from runtimes.defaults import SET_DEFAULT_NODE, SET_DEFAULT_PHP
        from sites import observation
        from sites.change import CREATE_SITE
        from sites.node_change import SET_SITE_NODE

        (alpha, runtime), *others = SITES
        apply_change(
            self, CREATE_SITE, PreparationInputs(runtime, alpha, (alpha + ".example.com",))
        )
        source = observation.COMMON_SOURCE + "\nidentities = []\n"
        for identifier, runtime in others:
            source += (
                f"settings = setting({identifier!r}, [{identifier + '.example.com'!r}], "
                f"{runtime!r})\n"
                "identity = free_identity(tuple(identities))\n"
                "proxy = free_identity((*identities, identity))\n"
                "identities += [identity, proxy]\n"
                "account = create_account(settings, identity)\n"
                "lock = create_layout(settings)\n"
                "configure_pool(settings, account, proxy)\n"
                f"publish_caddy({identifier!r}, caddy_file(settings), None)\n"
                "os.close(lock)\n"
            )
        self.native(observation.python_command(source, ()))
        apply_change(self, SET_DEFAULT_PHP, PreparationInputs(DEFAULT_PHP))
        apply_change(self, ADD_RUNTIME, PreparationInputs(NODE))
        apply_change(self, SET_DEFAULT_NODE, PreparationInputs(NODE))
        apply_change(self, SET_SITE_NODE, PreparationInputs(NODE, alpha))

    def checkpoint_reviews(self) -> None:
        """Record one discovery and every repeated review for the fast replay."""
        from discovery.observations import collect
        from operations import engine
        from operations.inputs import decode_inputs

        with self.shell() as shell:
            collect(shell)
            for slug, inputs in RECORDED_REVIEWS:
                kind = engine.kind_of(slug)
                if kind is None:
                    self.fail("Unknown kind " + slug)
                decoded = decode_inputs(inputs, kind.input_choices, kind.input_shape)
                review = kind.review(kind.inspect(shell, decoded), decoded)
                self.assertTrue(review.no_changes, (slug, inputs, review.refusals, review.effects))
            self.checkpoint("reconstruction-26.04", shell)

    def start(
        self, root: Path, fingerprint: str, reviews: tuple[tuple[str, dict[str, object]], ...]
    ) -> subprocess.Popen[str]:
        """Start one controller with its own database, key file and trust file."""
        target = self.target()
        root.mkdir()
        key = root / "id_ed25519"
        subprocess.run(  # noqa: S603 - the test's own key
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "s5", "-f", str(key)],  # noqa: S607
            check=True,
        )
        public = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        self.native(
            f"home=$(getent passwd {target.user or 'root'} | cut -d: -f6); "
            f"printf '%s\\n' '{public}' >>\"$home/.ssh/authorized_keys\""
        )
        environment = os.environ | {
            "S5_DATABASE": str(root / "controller.sqlite3"),
            "S5_PORT": str(target.port),
            "S5_USER": target.user or "root",
            "S5_FINGERPRINT": fingerprint,
            "S5_REVIEWS": json.dumps(reviews),
            "BARECTL_SSH_APPROVED_KEYS": json.dumps({"controller": str(key)}),
            "BARECTL_SSH_KNOWN_HOSTS": str(root / "known_hosts"),
            "BARECTL_SSH_CONFIG": os.devnull,
            "SSH_AUTH_SOCK": "",
        }
        return subprocess.Popen(  # noqa: S603 - the test's own controller
            [sys.executable, "-c", _CONTROLLER],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def finish(self, process: subprocess.Popen[str]) -> _Report:
        try:
            stdout, stderr = process.communicate(timeout=150)
        finally:
            if process.poll() is None:
                process.kill()
        self.assertEqual(process.returncode, 0, stderr[-3000:])
        value = json.loads(stdout.strip().splitlines()[-1])
        if not isinstance(value, dict):
            self.fail("The controller did not report its reconstruction.")
        return cast(_Report, value)
