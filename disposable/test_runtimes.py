"""Real target-runtime refusal, reconstruction and constrained-memory proof."""

import json
import os
import shlex
import sys
import time
from typing import override

from django.test import tag

from discovery.observations import collect
from operations import engine, native
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from runtimes import change, observation

from .docker import docker
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class RuntimeNativeBehavior(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""
    records: tuple[str, ...] = ("unknown-runtime-26.04", "runtime-protection-fault-26.04")

    @override
    def tearDown(self) -> None:
        try:
            self.native("systemctl reset-failed php-fpm@php84.service php-fpm@php85.service")
        finally:
            super().tearDown()

    def apply_runtime(self, entry: str, *, missing_cache: bool = False) -> engine.ResultLine:
        inputs = PreparationInputs(entry)
        with self.shell() as shell:
            evidence = change.inspect(shell, inputs)
            draft = change.review(evidence, inputs)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertFalse(draft.no_changes)
            values = evidence.native
            if values is None:
                self.fail("No runtime evidence.")
            context = engine.BodyContext(
                native.new_unit_name(), str(values["boot"]), int(str(values["uptime"])) + 90000
            )
            review = ChangeReview(document=draft.document, sites_read="", sites_digest="")
            body = change.body(review.document, context)
            path = engine.body_path(context.unit)
            self.assertEqual(
                shell.run(
                    shlex.join(engine.stage_command(path, change.BODY_SHA256)), stdin=body.source
                ).exit_status,
                0,
            )
            if missing_cache:
                self.native(
                    "cp /etc/hosts /run/runtime-hosts; printf '\\n127.0.0.1 "
                    "cache.nixos.org\\n' >>/etc/hosts"
                )
                self.native(
                    "cp /etc/php-fpm/php85/php.ini /run/runtime-unrelated-ini; "
                    "sed -i 's/opcache.validate_permission=1/opcache.validate_permission=0/' "
                    "/etc/php-fpm/php85/php.ini; systemctl restart php-fpm@php85.service"
                )
            try:
                payload = engine.payload(change.ADD_RUNTIME, review, context, body, path)
                self.assertEqual(
                    shell.run(
                        shlex.join(native.submission(context.unit, payload, collect=True))
                    ).exit_status,
                    0,
                )
                deadline = time.monotonic() + 30
                outcome = engine.read_result(shell, context.unit)
                while outcome is None and time.monotonic() < deadline:
                    time.sleep(0.1)
                    outcome = engine.read_result(shell, context.unit)
                if outcome is None:
                    self.fail(self.native(f"journalctl -u {context.unit} -n 30"))
                self.native(f"test ! -e {shlex.quote(path)}")
                return outcome
            finally:
                if missing_cache:
                    self.native("cat /run/runtime-hosts >/etc/hosts; rm /run/runtime-hosts")
                    self.native(
                        "cp /run/runtime-unrelated-ini /etc/php-fpm/php85/php.ini; "
                        "rm /run/runtime-unrelated-ini; systemctl restart php-fpm@php85.service"
                    )

    def test_missing_cache_refuses_before_profile_configuration_or_service_changes(self) -> None:
        before = self.native(
            "find /etc/php-fpm /etc/systemd/system -type f -exec sha256sum {} "
            "+ | sort; readlink /nix/var/nix/profiles/barectl/php84; readlink "
            "/nix/var/nix/profiles/barectl/php85"
        )
        outcome = self.apply_runtime("nodejs_24", missing_cache=True)
        self.assertEqual(outcome.result_class, "refused")
        self.assertEqual(outcome.reason, "runtime_cache")
        self.native(
            "test ! -e /nix/var/nix/profiles/barectl/nodejs_24; test ! -e /etc/php-fpm/nodejs_24"
        )
        self.assertEqual(
            self.native(
                "find /etc/php-fpm /etc/systemd/system -type f -exec sha256sum {} "
                "+ | sort; readlink /nix/var/nix/profiles/barectl/php84; readlink "
                "/nix/var/nix/profiles/barectl/php85"
            ),
            before,
        )

    def test_node_addition_is_profile_only_even_when_an_unrelated_php_master_has_a_fault(
        self,
    ) -> None:
        self.native(
            "cp /etc/php-fpm/php84/php.ini /run/runtime-ini; sed -i "
            "'s/opcache.validate_permission=1/opcache.validate_permission=0/' "
            "/etc/php-fpm/php84/php.ini; systemctl restart "
            "php-fpm@php84.service"
        )
        try:
            before = self.native(
                "systemctl list-units --type=service --state=running --no-legend "
                "--no-pager | awk '{print $1}' | sort"
            )
            outcome = self.apply_runtime("nodejs_22")
            self.assertEqual(outcome.result_class, "succeeded")
            self.native(
                "test -x /nix/var/nix/profiles/barectl/nodejs_22/bin/node; test ! "
                "-e /etc/php-fpm/nodejs_22"
            )
            self.assertEqual(
                self.native(
                    "systemctl list-units --type=service --state=running --no-legend "
                    "--no-pager | awk '{print $1}' | sort"
                ),
                before,
            )
        finally:
            self.native(
                "cp /run/runtime-ini /etc/php-fpm/php84/php.ini; rm "
                "/run/runtime-ini; systemctl restart php-fpm@php84.service"
            )

    def test_unknown_store_path_is_reported_without_adoption(self) -> None:
        self.native(
            "/nix/var/nix/profiles/default/bin/nix-env --profile "
            "/nix/var/nix/profiles/barectl/php84 --set "
            "/nix/var/nix/profiles/barectl/caddy"
        )
        try:
            with self.shell() as shell:
                observed = collect(shell)
                self.checkpoint("unknown-runtime-26.04", shell)
            row = next(row for row in observed.runtimes if row.entry == "php84")
            self.assertIn("Unknown profile store path", row.problem)
            self.assertIn("pools", row.problem)
        finally:
            self.native(
                "/nix/var/nix/profiles/default/bin/nix-env --profile "
                "/nix/var/nix/profiles/barectl/php84 --rollback"
            )

    def test_weakened_master_is_one_protection_fault_blocking_its_pools(self) -> None:
        self.native(
            "cp /etc/php-fpm/php84/php.ini /run/runtime-ini; sed -i "
            "'s/opcache.validate_permission=1/opcache.validate_permission=0/' "
            "/etc/php-fpm/php84/php.ini; systemctl restart "
            "php-fpm@php84.service"
        )
        try:
            with self.shell() as shell:
                observed = collect(shell)
                self.checkpoint("runtime-protection-fault-26.04", shell)
            faults = [row for row in observed.runtimes if row.problem]
            self.assertEqual(len(faults), 1)
            self.assertEqual(faults[0].entry, "php84")
            self.assertIn("Pool changes on this master are blocked", faults[0].problem)
        finally:
            self.native(
                "cp /run/runtime-ini /etc/php-fpm/php84/php.ini; rm "
                "/run/runtime-ini; systemctl restart php-fpm@php84.service"
            )

    def test_a_replaced_private_socket_does_not_adopt_a_second_same_version_master(self) -> None:
        self.native(
            "rm /run/php-fpm/php84/diagnostic.sock; systemd-run --quiet "
            "--unit=runtime-other-master "
            "/nix/var/nix/profiles/barectl/php84/bin/php-fpm -y "
            "/etc/php-fpm/php84/php-fpm.conf -c /etc/php-fpm/php84/php.ini"
        )
        try:
            time.sleep(1)
            with self.shell() as shell:
                evidence = change.inspect(shell, PreparationInputs("php84"))
            if evidence.native is None or evidence.architecture is None:
                self.fail("The replaced socket fixture produced no native evidence.")
            rows = observation.observations(evidence.native["runtimes"], evidence.architecture)
            row = next(row for row in rows if row.entry == "php84")
            self.assertFalse(row.manageable)
            self.assertIn("Protection fault", row.problem)
            raw_rows = evidence.native["runtimes"]
            if not isinstance(raw_rows, list):
                self.fail("No native runtime list.")
            raw = next(
                item for item in raw_rows if isinstance(item, dict) and item.get("entry") == "php84"
            )
            self.assertIs(raw.get("socket_owned"), False)
            self.assertIn('"opcache.validate_permission":"1"', str(raw.get("response")))
        finally:
            self.native(
                "systemctl stop runtime-other-master; systemctl restart php-fpm@php84.service"
            )

    def test_passive_discovery_does_not_execute_unknown_diagnostic_pool_directives(self) -> None:
        marker = "/var/lib/php-fpm/php84/diagnostic/tmp/passive-discovery-marker"
        prelude = "<?php file_put_contents(" + repr(marker) + ", 'executed');"
        self.native(
            "cp /etc/php-fpm/php84/pools/diagnostic.conf /run/runtime-pool; "
            "printf %s "
            + shlex.quote(prelude)
            + " >/etc/php-fpm/diagnostics/prelude.php; "
            + "chown root:php-probe /etc/php-fpm/diagnostics/prelude.php; "
            + "chmod 640 /etc/php-fpm/diagnostics/prelude.php; "
            + "printf '%s\\n' "
            + shlex.quote(
                "php_admin_value[auto_prepend_file] = /etc/php-fpm/diagnostics/prelude.php"
            )
            + " >>/etc/php-fpm/php84/pools/diagnostic.conf; "
            + "systemctl restart php-fpm@php84.service"
        )
        try:
            with self.shell() as shell:
                observed = collect(shell)
            fault = next(row for row in observed.runtimes if row.entry == "php84")
            self.assertFalse(fault.manageable)
            self.native("test ! -e " + shlex.quote(marker))
        finally:
            self.native(
                "cp /run/runtime-pool /etc/php-fpm/php84/pools/diagnostic.conf; "
                "rm /run/runtime-pool /etc/php-fpm/diagnostics/prelude.php; "
                "rm -f " + shlex.quote(marker) + "; systemctl restart php-fpm@php84.service"
            )

    def test_passive_discovery_does_not_execute_stale_loaded_pool_directives(self) -> None:
        marker = "/var/lib/php-fpm/php84/diagnostic/tmp/stale-pool-marker"
        prelude_path = "/var/lib/php-fpm/php84/diagnostic/tmp/stale-prelude.php"
        prelude = "<?php file_put_contents(" + repr(marker) + ", 'executed');"
        self.native(
            "cp /etc/php-fpm/php84/pools/diagnostic.conf /run/runtime-stale-pool; "
            "printf %s " + shlex.quote(prelude) + " >" + shlex.quote(prelude_path) + "; "
            "chown php-probe:php-probe " + shlex.quote(prelude_path) + "; "
            "printf '%s\\n' "
            + shlex.quote("php_admin_value[auto_prepend_file] = " + prelude_path)
            + " >>/etc/php-fpm/php84/pools/diagnostic.conf; "
            "systemctl restart php-fpm@php84.service; "
            "cp /run/runtime-stale-pool /etc/php-fpm/php84/pools/diagnostic.conf"
        )
        try:
            with self.shell() as shell:
                observed = collect(shell)
            self.native("test ! -e " + shlex.quote(marker))
            self.assertTrue(any(row.entry == "php84" for row in observed.runtimes))
        finally:
            self.native(
                "cp /run/runtime-stale-pool /etc/php-fpm/php84/pools/diagnostic.conf; "
                "rm /run/runtime-stale-pool " + shlex.quote(prelude_path) + "; "
                "rm -f " + shlex.quote(marker) + "; systemctl restart php-fpm@php84.service"
            )

    def test_passive_discovery_does_not_execute_stale_loaded_ini_path_sections(self) -> None:
        marker = "/var/lib/php-fpm/php84/diagnostic/tmp/stale-ini-marker"
        prelude_path = "/var/lib/php-fpm/php84/diagnostic/tmp/stale-path-prelude.php"
        prelude = "<?php file_put_contents(" + repr(marker) + ", 'executed');"
        self.native(
            "cp /etc/php-fpm/php84/php.ini /run/runtime-stale-ini; "
            "printf %s " + shlex.quote(prelude) + " >" + shlex.quote(prelude_path) + "; "
            "chown php-probe:php-probe " + shlex.quote(prelude_path) + "; "
            "printf '%s\\n' "
            + shlex.quote("[PATH=/etc/php-fpm/diagnostics]\nauto_prepend_file=" + prelude_path)
            + " >>/etc/php-fpm/php84/php.ini; "
            "systemctl restart php-fpm@php84.service; "
            "cp /run/runtime-stale-ini /etc/php-fpm/php84/php.ini"
        )
        try:
            with self.shell() as shell:
                observed = collect(shell)
            self.native("test ! -e " + shlex.quote(marker))
            self.assertTrue(any(row.entry == "php84" for row in observed.runtimes))
        finally:
            self.native(
                "cp /run/runtime-stale-ini /etc/php-fpm/php84/php.ini; "
                "rm /run/runtime-stale-ini " + shlex.quote(prelude_path) + "; "
                "rm -f " + shlex.quote(marker) + "; systemctl restart php-fpm@php84.service"
            )

    def test_a_cached_unit_cannot_load_an_unreviewed_ini_before_passive_discovery(self) -> None:
        self.cached_ini_is_refused(reset_manager=False)

    def test_cached_unsafe_start_is_refused_after_manager_reload(self) -> None:
        self.cached_ini_is_refused(reset_manager=True)

    def cached_ini_is_refused(self, *, reset_manager: bool) -> None:
        marker = "/var/lib/php-fpm/php84/diagnostic/tmp/cached-unit-marker"
        prelude_path = "/var/lib/php-fpm/php84/diagnostic/tmp/cached-unit-prelude.php"
        alternate = "/etc/php-fpm/php84/alternate.ini"
        dropin = "/etc/systemd/system/php-fpm@php84.service.d"
        prelude = "<?php file_put_contents(" + repr(marker) + ", 'executed');"
        override = (
            "[Service]\nExecStart=\n"
            "ExecStart=/nix/var/nix/profiles/barectl/php84/bin/php-fpm "
            "-y /etc/php-fpm/php84/php-fpm.conf -c " + alternate + "\n"
        )
        self.native(
            "systemctl stop php-fpm@php84.service; mkdir " + dropin + "; "
            "cp /etc/php-fpm/php84/php.ini " + alternate + "; "
            "printf %s " + shlex.quote(prelude) + " >" + shlex.quote(prelude_path) + "; "
            "chown php-probe:php-probe " + shlex.quote(prelude_path) + "; "
            "printf '%s\\n' "
            + shlex.quote("auto_prepend_file=" + prelude_path)
            + " >>"
            + alternate
            + "; "
            "printf %s " + shlex.quote(override) + " >" + dropin + "/override.conf; "
            "systemctl daemon-reload; rm " + dropin + "/override.conf; "
            "rmdir " + dropin + "; systemctl start php-fpm@php84.service"
        )
        try:
            if reset_manager:
                self.native("systemctl daemon-reload")
            with self.shell() as shell:
                observed = collect(shell)
            self.native("test ! -e " + shlex.quote(marker))
            row = next(row for row in observed.runtimes if row.entry == "php84")
            self.assertFalse(row.manageable)
        finally:
            self.native(
                "systemctl stop php-fpm@php84.service; rm -f "
                + alternate
                + " "
                + shlex.quote(prelude_path)
                + " "
                + shlex.quote(marker)
                + "; systemctl daemon-reload; "
                "systemctl restart php-fpm@php84.service php-fpm@php85.service"
            )

    def test_cached_environment_file_does_not_enable_unreviewed_scan_configuration(self) -> None:
        marker = "/var/lib/php-fpm/php84/diagnostic/tmp/environment-marker"
        prelude_path = "/var/lib/php-fpm/php84/diagnostic/tmp/environment-prelude.php"
        scan = "/var/lib/php-fpm/php84/diagnostic/tmp/environment-scan"
        environment = "/run/runtime-php84-environment"
        dropin = "/etc/systemd/system/php-fpm@php84.service.d"
        override = "[Service]\nEnvironmentFile=" + environment + "\n"
        prelude = "<?php file_put_contents(" + repr(marker) + ", 'executed');"
        self.native(
            "systemctl stop php-fpm@php84.service; mkdir " + dropin + " " + scan + "; "
            "printf %s " + shlex.quote(prelude) + " >" + shlex.quote(prelude_path) + "; "
            "chown php-probe:php-probe " + shlex.quote(prelude_path) + "; "
            "printf '%s\\n' "
            + shlex.quote("auto_prepend_file=" + prelude_path)
            + " >"
            + scan
            + "/extra.ini; "
            "printf '%s\\n' " + shlex.quote("PHP_INI_SCAN_DIR=" + scan) + " >" + environment + "; "
            "printf %s " + shlex.quote(override) + " >" + dropin + "/override.conf; "
            "systemctl daemon-reload; rm " + dropin + "/override.conf; "
            "rmdir " + dropin + "; systemctl start php-fpm@php84.service; "
            "test ! -e " + shlex.quote(marker)
        )
        try:
            with self.shell() as shell:
                observed = collect(shell)
            self.native("test ! -e " + shlex.quote(marker))
            row = next(row for row in observed.runtimes if row.entry == "php84")
            self.assertFalse(row.manageable)
        finally:
            self.native(
                "systemctl stop php-fpm@php84.service; rm -f "
                + environment
                + " "
                + shlex.quote(prelude_path)
                + " "
                + shlex.quote(marker)
                + "; rm -rf "
                + scan
                + "; systemctl daemon-reload; "
                "systemctl restart php-fpm@php84.service php-fpm@php85.service"
            )

    def test_manager_reload_requires_restart_to_reestablish_the_executed_command(self) -> None:
        self.native("systemctl daemon-reload")
        try:
            with self.shell() as shell:
                observed = collect(shell, sites=False)
            self.assertFalse(
                next(row for row in observed.runtimes if row.entry == "php84").manageable
            )
            self.native("systemctl reload php-fpm@php84.service")
            with self.shell() as shell:
                after_reload = collect(shell, sites=False)
            self.assertFalse(
                next(row for row in after_reload.runtimes if row.entry == "php84").manageable
            )
            self.native("systemctl restart php-fpm@php84.service php-fpm@php85.service")
            with self.shell() as shell:
                after_restart = collect(shell, sites=False)
            self.assertTrue(all(row.manageable for row in after_restart.runtimes))
        finally:
            self.native("systemctl restart php-fpm@php84.service php-fpm@php85.service")

    def test_a_separate_php_master_can_be_added_without_touching_a_faulty_master(self) -> None:
        self.native(
            "systemctl stop php-fpm@php85.service; "
            "mv /nix/var/nix/profiles/barectl/php85 /run/runtime-php85-profile; "
            "mv /etc/php-fpm/php85 /run/runtime-php85-config; "
            "cp /etc/php-fpm/php84/php.ini /run/runtime-php84-ini; "
            "sed -i 's/opcache.validate_permission=1/opcache.validate_permission=0/' "
            "/etc/php-fpm/php84/php.ini; systemctl restart php-fpm@php84.service"
        )
        try:
            self.native("chgrp root /etc/php-fpm/diagnostics/probe.php")
            try:
                with self.shell() as shell:
                    unsafe = change.review(
                        change.inspect(shell, PreparationInputs("php85")),
                        PreparationInputs("php85"),
                    )
                self.assertFalse(unsafe.eligible, unsafe.refusals)
                self.native(
                    "test ! -e /nix/var/nix/profiles/barectl/php85; test ! -e /etc/php-fpm/php85"
                )
            finally:
                self.native("chgrp php-probe /etc/php-fpm/diagnostics/probe.php")
            shared = self.native(
                "stat -c '%n %y %z' /etc/php-fpm/diagnostics/probe.php "
                "/etc/systemd/system/php-fpm@.service; "
                "systemctl show php-fpm@php84.service -p MainPID -p InvocationID"
            )
            result = self.apply_runtime("php85")
            self.assertEqual(result.result_class, "succeeded", result)
            self.assertEqual(
                self.native(
                    "stat -c '%n %y %z' /etc/php-fpm/diagnostics/probe.php "
                    "/etc/systemd/system/php-fpm@.service; "
                    "systemctl show php-fpm@php84.service -p MainPID -p InvocationID"
                ),
                shared,
            )
            with self.shell() as shell:
                observed = collect(shell, sites=False)
            by_entry = {row.entry: row for row in observed.runtimes}
            self.assertFalse(by_entry["php84"].manageable)
            self.assertTrue(by_entry["php85"].manageable, by_entry["php85"].problem)
        finally:
            self.native(
                "systemctl stop php-fpm@php85.service; "
                "rm -f /nix/var/nix/profiles/barectl/php85; "
                "rm -rf /etc/php-fpm/php85; "
                "mv /run/runtime-php85-profile /nix/var/nix/profiles/barectl/php85; "
                "mv /run/runtime-php85-config /etc/php-fpm/php85; "
                "cp /run/runtime-php84-ini /etc/php-fpm/php84/php.ini; "
                "rm /run/runtime-php84-ini; "
                "chgrp php-probe /etc/php-fpm/diagnostics/probe.php; "
                "systemctl restart php-fpm@php84.service php-fpm@php85.service"
            )

    def test_supported_pool_reload_establishes_a_new_safe_load_boundary(self) -> None:
        original = self.native("systemctl show php-fpm@php84.service -p MainPID -p InvocationID")
        self.native(
            "touch /etc/php-fpm/php84/pools/diagnostic.conf; systemctl reload php-fpm@php84.service"
        )
        deadline = time.monotonic() + 15
        while True:
            with self.shell() as shell:
                observed = collect(shell, sites=False)
            row = next(row for row in observed.runtimes if row.entry == "php84")
            if row.manageable or time.monotonic() >= deadline:
                break
            time.sleep(0.2)
        self.assertTrue(row.manageable, row.problem)
        self.assertEqual(
            self.native("systemctl show php-fpm@php84.service -p MainPID -p InvocationID"),
            original,
        )

    def test_direct_unbound_reload_refuses_the_passive_probe(self) -> None:
        self.native("systemctl kill --kill-whom=main --signal=USR2 php-fpm@php84.service")
        try:
            time.sleep(0.3)
            with self.shell() as shell:
                observed = collect(shell)
            row = next(row for row in observed.runtimes if row.entry == "php84")
            self.assertFalse(row.manageable)
            self.assertIn("Protection fault", row.problem)
        finally:
            self.native("systemctl restart php-fpm@php84.service")


@tag(SCENARIO_TAG)
class RuntimeSmallHost(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""

    def test_both_masters_keep_one_diagnostic_worker_within_a_one_gib_memory_limit(self) -> None:
        container = os.environ["BARECTL_SSH_TEST_CONTAINER"]
        self.native(
            "getent shadow php-probe | awk -F: "
            + shlex.quote("$2 ~ /^(!|\\*)/ { found=1 } END { exit !found }")
        )
        docker("update", "--memory", "1073741824", "--memory-swap", "1073741824", container)
        self.assertEqual(
            docker("inspect", "-f", "{{.HostConfig.Memory}}", container).strip(), "1073741824"
        )
        self.assertEqual(self.native("cat /sys/fs/cgroup/memory.max").strip(), "1073741824")
        with self.shell() as shell:
            observed = collect(shell)
        self.assertTrue(all(row.manageable for row in observed.runtimes))
        busy = self.native(
            "systemctl show php-fpm@php84.service php-fpm@php85.service -p Id "
            "-p MemoryCurrent -p MemoryPeak; cat "
            "/sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.peak"
        )
        # Past the former ten-second idle timeout, the static worker is still the same one.
        workers = {
            entry: self.native(
                f"main=$(systemctl show --value -p MainPID php-fpm@{entry}.service); "
                "cat /proc/$main/task/$main/children"
            ).split()
            for entry in ("php84", "php85")
        }
        self.native("sleep 12")
        idle = self.native(
            "systemctl show php-fpm@php84.service php-fpm@php85.service -p Id "
            "-p MemoryCurrent -p MemoryPeak; cat "
            "/sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.peak"
        )
        for entry in ("php84", "php85"):
            children = self.native(
                f"main=$(systemctl show --value -p MainPID php-fpm@{entry}.service); "
                "cat /proc/$main/task/$main/children"
            )
            self.assertEqual(children.split(), workers[entry])
            self.assertEqual(len(workers[entry]), 1)
            self.native(
                f"grep -Fx 'pm = static' /etc/php-fpm/{entry}/pools/diagnostic.conf && "
                f"grep -Fx 'pm.max_children = 1' /etc/php-fpm/{entry}/pools/diagnostic.conf && "
                f"! grep -F 'process_idle_timeout' /etc/php-fpm/{entry}/pools/diagnostic.conf"
            )
        for entry in ("php84", "php85"):
            denied = self.native(
                "runuser -u php-probe -- python3 -c "
                + shlex.quote(
                    "import socket; s=socket.socket(socket.AF_UNIX); "
                    f"s.connect('/run/php-fpm/{entry}/diagnostic.sock')"
                )
                + " 2>&1; printf '\\nstatus=%s\\n' $?"
            )
            self.assertIn("Permission denied", denied)
            self.assertNotIn("status=0", denied)
        sys.stdout.write(
            "RUNTIME_MEMORY_EVIDENCE "
            + json.dumps({"limit": 1073741824, "busy": busy, "idle": idle})
            + "\n"
        )
