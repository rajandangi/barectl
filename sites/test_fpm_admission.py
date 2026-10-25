"""A site master stays bound across a systemd reload, and a foreign command never is.

A change that writes a unit file runs ``systemctl daemon-reload``; systemd 259 clears the
running invocation's ``ExecStart`` runtime fields. The configured command, the process, its
cgroup and its invocation still bind the master, so a later PHP change must read it rather
than report the site as unverifiable ([automation](../docs/automation.md#fencing-site-changes)).
"""

from typing import ClassVar
from unittest import TestCase

from sites.bodies.site_fpm import sfp_execution

IDENTIFIER = "alpha"
ENTRY = "php84"
START = 1_792_000_000_000_000
MONOTONIC = 88_000_000_000
PID = 4321


def executable() -> str:
    return f"/nix/var/nix/profiles/barectl/{ENTRY}/bin/php-fpm"


def base() -> str:
    return f"/etc/php-fpm/sites/{IDENTIFIER}/{ENTRY}"


def context(*, cleared: bool = False, chmod_cleared: bool = False) -> dict[str, object]:
    runtime = [0] * 7 if cleared else [START, MONOTONIC, 0, 0, PID, 0, 0]
    post = (
        [0] * 7
        if (cleared or chmod_cleared)
        else [START, MONOTONIC, START + 1, MONOTONIC + 1, PID, 1, 0]
    )
    return {
        "MainPID": PID,
        "ControlGroup": f"/system.slice/php-fpm-site-{ENTRY}@{IDENTIFIER}.service",
        "Type": "notify",
        "ExecMainStartTimestamp": START,
        "ExecMainStartTimestampMonotonic": MONOTONIC,
        "ExecStart": [
            [
                executable(),
                [
                    executable(),
                    "-F",
                    "-y",
                    base() + "/php-fpm.conf",
                    "-c",
                    base() + "/php.ini",
                ],
                False,
                *runtime,
            ]
        ],
        "ExecStartPost": [
            [
                "/usr/bin/chmod",
                [
                    "/usr/bin/chmod",
                    "0600",
                    f"/run/php-fpm/sites/{IDENTIFIER}/{ENTRY}/status/listen.sock",
                ],
                False,
                *post,
            ]
        ],
        "ExecReload": [],
        "Environment": [],
        "EnvironmentFiles": [],
        "PassEnvironment": [],
        "UnsetEnvironment": [],
        "KillSignal": 3,
        "TimeoutStopUSec": 310000000,
        "SendSIGKILL": True,
        "InvocationID": [1] * 16,
        "ActiveState": "active",
        "SubState": "running",
        "LoadState": "loaded",
        "FragmentPath": f"/etc/systemd/system/php-fpm-site-{ENTRY}@.service",
        "DropInPaths": [],
    }


class MasterExecutionTests(TestCase):
    identifier: ClassVar[str] = IDENTIFIER

    def test_a_running_master_binds_its_process(self) -> None:
        self.assertEqual(sfp_execution(IDENTIFIER, ENTRY, context()), START)

    def test_a_reloaded_unit_derives_its_start_from_the_preserved_monotonic_clock(self) -> None:
        found = sfp_execution(IDENTIFIER, ENTRY, context(cleared=True))
        if found is None:
            self.fail("A reloaded master is no longer bound to its unit.")
        self.assertGreater(found, 1_700_000_000_000_000)

    def test_a_foreign_or_half_cleared_command_is_refused(self) -> None:
        foreign = context()
        foreign["ExecStart"] = [
            [
                "/bin/true",
                ["/bin/true"],
                False,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        ]
        half = context()
        commands = half["ExecStart"]
        if not isinstance(commands, list):
            self.fail("The fixture is not a command list.")
        commands[0][7] = PID + 1
        for invalid in (
            context(chmod_cleared=True),
            foreign,
            half,
            {**context(), "Type": "simple"},
            {**context(), "KillSignal": 15},
            {**context(), "SendSIGKILL": False},
            {**context(), "ActiveState": "reloading"},
            {**context(), "FragmentPath": "/etc/systemd/system/php-fpm@.service"},
            {**context(), "Environment": ["X=1"]},
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(sfp_execution(IDENTIFIER, ENTRY, invalid))
