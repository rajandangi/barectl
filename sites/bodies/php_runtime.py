"""Native site PHP transitions preserve admission and post-response work (ADR 0038)."""

import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from typing import TypedDict

import sites.bodies.admission as admission
import sites.bodies.common as common
from sites.bodies.site_fpm import site_fpm_idle
from sites.serving import php_directory


class PHPState(TypedDict):
    native: common.NativeState
    proxy: admission.ProxyState
    services: dict[str, dict[str, object] | None]
    profiles: dict[str, str]
    modules: dict[str, list[str]]
    builtins: dict[str, list[str]]
    wrapper_runtime: str
    complete: bool
    digest: str


def php_services(
    identifier: str, names: list[str]
) -> tuple[dict[str, dict[str, object] | None], dict[str, str], dict[str, object]]:
    services: dict[str, dict[str, object] | None] = {}
    profiles: dict[str, str] = {}
    masters: dict[str, object] = {}
    for entry in ("php84", "php85"):
        candidate = common.setting(identifier, names, entry)
        profile = os.path.realpath(f"/nix/var/nix/profiles/barectl/{entry}")
        profiles[entry] = (
            profile
            if profile in common.KNOWN_PHP.get(os.uname().machine, {}).get(entry, ())
            else ""
        )
        active = common.run(
            [
                "systemctl",
                "show",
                "--value",
                "-p",
                "ActiveState",
                f"php-fpm-site-{entry}@{identifier}.service",
            ],
            check=False,
        ).strip()
        if active not in ("active", "inactive"):
            raise ValueError("A site PHP service has an uncertain native outcome.")
        evidence = common.site_fpm_read(candidate) if active == "active" else None
        if active == "active" and evidence is None:
            raise ValueError("An active PHP service has unavailable protection evidence.")
        services[entry] = evidence
        if evidence is not None:
            masters[entry] = {
                key: evidence[key] for key in ("pid", "invocation", "load", "app_pids")
            }
    return services, profiles, masters


def php_modules(profiles: dict[str, str], *, bare: bool = False) -> dict[str, list[str]]:
    observed: dict[str, list[str]] = {}
    for entry, path in profiles.items():
        if not path:
            observed[entry] = []
            continue
        raw = common.run(
            [
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                path + "/bin/php-fpm",
                *(["-n", "-m"] if bare else ["-m"]),
            ]
        )
        sections = raw.split("\n[Zend Modules]\n")
        if len(sections) != 2 or not sections[0].startswith("[PHP Modules]\n"):
            raise ValueError("Installed FPM module capabilities are unavailable.")
        names = [line for line in (sections[0][14:] + sections[1]).splitlines() if line]
        if not names or any(
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9_ .-]{0,99}", name) for name in names
        ):
            raise ValueError("Installed FPM module capabilities are malformed.")
        observed[entry] = sorted(set(names))
    return observed


def missing_php_modules(state: PHPState, selected: str) -> list[str]:
    required: set[str] = set()
    for entry, service in state["services"].items():
        if service is not None:
            extensions = service.get("extensions")
            if not isinstance(extensions, list) or any(
                not isinstance(name, str) for name in extensions
            ):
                raise ValueError("Current application modules are unavailable.")
            required.update(set(extensions) - set(state["builtins"][entry]))
    return sorted(required - set(state["modules"][selected]))


def php_state(identifier: str) -> PHPState:
    observed = common.native_state(identifier, "", site_only=True)
    row = next((s for s in observed["sites"] if s["identifier"] == identifier), None)
    if row is None or not row["names"]:
        raise ValueError("The site has no supported native HTTP route.")
    if row["state"] != "complete" and row["problem"] != common.PHP_TRANSITION_INCOMPLETE:
        raise ValueError("Unsupported site configuration: " + row["problem"])
    settings = common.setting(identifier, row["names"], "php84")
    account = common.site_account(identifier)
    if account is None:
        raise ValueError("The site account is missing.")
    uid, gid = common.account_ids(settings, account)
    if common.directory_shape(settings, uid, gid) != ("complete", ""):
        raise ValueError("The site layout is not supported.")
    proxy = admission.haproxy_state(settings)
    wrapper_runtime = common.php_wrapper_runtime(settings)
    if not wrapper_runtime and common.php_wrapper_selections(settings) is None:
        raise ValueError("The site's PHP commands are administrator-owned or inconsistent.")
    services, profiles, masters = php_services(identifier, row["names"])
    modules = php_modules(profiles)
    builtins = php_modules(profiles, bare=True)
    ready = proxy["ready"]
    if not ready or any(services[entry] is None for entry in ready):
        raise ValueError("Live admission does not have a verified serving PHP service.")
    if services[proxy["persistent"]] is None:
        raise ValueError("The native restart selection has no verified PHP service.")
    selected = proxy["selection"]
    other = "php85" if selected == "php84" else "php84"
    complete = bool(
        selected
        and selected == proxy["persistent"] == wrapper_runtime
        and services[other] is None
        and not source_php_path(identifier, other).exists()
        and not source_php_path(identifier, other).is_symlink()
    )
    paths = [
        f"/var/www/{identifier}/.deploy.lock",
        f"/var/www/{identifier}/bin",
        *(f"/var/www/{identifier}/bin/{name}" for name in ("php", "composer", "wp")),
        f"/var/lib/haproxy/sites/{identifier}.state",
        *(f"/nix/var/nix/profiles/barectl/{entry}" for entry in profiles),
    ]
    metadata = {path: common.fingerprint(path) for path in paths}
    digest = hashlib.sha256(
        common.canonical(
            {
                "native": observed["digest"],
                "proxy": proxy["digest"],
                "masters": masters,
                "modules": modules,
                "builtins": builtins,
                "files": metadata,
            }
        ).encode()
    ).hexdigest()
    return {
        "native": observed,
        "proxy": proxy,
        "services": services,
        "profiles": profiles,
        "modules": modules,
        "builtins": builtins,
        "wrapper_runtime": wrapper_runtime,
        "complete": complete,
        "digest": digest,
    }


def php_settings(identifier: str, state: PHPState, entry: str) -> SimpleNamespace:
    row = next(s for s in state["native"]["sites"] if s["identifier"] == identifier)
    return common.setting(
        identifier,
        row["names"],
        entry,
        https=row["https"],
        readiness=row["readiness"],
    )


def source_php_path(identifier: str, runtime: str) -> pathlib.Path:
    return pathlib.Path(php_directory(identifier, runtime))


def remove_stopped_php(settings: SimpleNamespace) -> None:
    """Remove one runtime's configuration, resuming an interrupted cleanup (ADR 0038).

    Only the exact canonical surviving subtree is removed: a partial removal from a crash
    between unlinks is admitted when the service is inactive, and any unknown entry, symlink
    or changed file refuses. Each step is idempotent, so a fresh review finishes cleanup.
    """
    unit = common.php_site_unit(settings.identifier, settings.runtime)
    properties = "--property=ActiveState,MainPID,Result,ExecMainStatus,LoadState"
    report = common.run(["systemctl", "show", unit, properties], check=False)
    values = common.unit_properties(report)
    if (
        common.retained_php_shape(settings, active=not common.php_service_inactive(values))
        == "unsupported"
    ):
        raise ValueError("Source PHP configuration changed before cleanup.")
    if values.get("ActiveState") == "active":
        common.run(["systemctl", "stop", unit])
        values = common.unit_properties(
            common.run(["systemctl", "show", unit, properties], check=False)
        )
    if (
        values.get("ActiveState") not in ("inactive", "failed")
        or values.get("MainPID") != "0"
        or values.get("ExecMainStatus") != "0"
        or values.get("Result") not in ("success", "")
    ):
        raise ValueError("The source PHP service did not exit normally.")
    if common.retained_php_shape(settings, active=False) == "unsupported":
        raise ValueError("Source PHP configuration changed before cleanup.")
    if values.get("LoadState") != "not-found":
        common.run(["systemctl", "--no-reload", "disable", unit])
    for name in common.site_fpm_files(settings):
        pathlib.Path(name).unlink(missing_ok=True)
    base = source_php_path(settings.identifier, settings.runtime)
    if (base / "pools").is_dir():
        (base / "pools").rmdir()
    if base.is_dir():
        base.rmdir()


def replace_php_wrapper(path: pathlib.Path, contents: str) -> None:
    before = common.fingerprint(str(path))
    if before is None or not common.safe(str(path)):
        raise ValueError("A PHP command preimage is unavailable.")
    descriptor, staged_name = tempfile.mkstemp(prefix=".php-runtime-", dir=path.parent)
    staged = pathlib.Path(staged_name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(contents)
            stream.flush()
            os.fchmod(stream.fileno(), 0o755)
            os.fsync(stream.fileno())
        if common.fingerprint(str(path)) != before:
            raise ValueError("A PHP command changed during staging.")
        os.replace(staged, path)
        parent = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        staged.unlink(missing_ok=True)


def start_target_php(
    settings: SimpleNamespace, before: PHPState, source: str
) -> dict[str, object] | None:
    identifier = settings.identifier
    source_evidence = before["services"][source]
    common.stage("target")
    common.start_site_fpm(settings)
    target = common.wait_site_fpm(settings)
    extensions = target["extensions"]
    if not isinstance(extensions, list) or any(not isinstance(name, str) for name in extensions):
        raise ValueError("Target loaded module evidence is unavailable.")
    if set(extensions) != set(before["modules"][settings.runtime]):
        raise ValueError("Target loaded modules differ from reviewed build capabilities.")
    if source_evidence is not None:
        refreshed = common.site_fpm_read(php_settings(identifier, before, source))
        if refreshed is None or any(
            refreshed[key] != source_evidence[key] for key in ("pid", "invocation", "app_pids")
        ):
            raise ValueError("Source PHP protection evidence changed before admission.")
        source_evidence = refreshed
    return source_evidence


def select_target_php(settings: SimpleNamespace, before: PHPState, source: str) -> None:
    identifier, selected = settings.identifier, settings.runtime
    common.stage("admission")
    if admission.hap_api(identifier, f"set server php/{selected} state ready"):
        raise ValueError("Target admission acknowledgement is unknown.")
    if admission.hap_api(identifier, f"set server php/{source} state maint"):
        raise ValueError("Source maintenance acknowledgement is unknown.")
    common.stage("persist")
    if admission.persist_proxy_state(settings) != selected:
        raise ValueError("Native restart state did not select the target.")
    common.stage("drain")
    if admission.hap_api(identifier, f"wait 10s srv-removable php/{source}", seconds=11) != "Done.":
        raise ValueError("Source admission remains in use.")
    current = admission.haproxy_state(settings)
    if (
        current["process"] != before["proxy"]["process"]
        or current["selection"] != selected
        or current["persistent"] != selected
    ):
        raise ValueError("Admission identity or persisted selection changed during drain.")


def finish_source_php(
    settings: SimpleNamespace,
    before: PHPState,
    source: str,
    source_evidence: dict[str, object] | None,
    descriptor: int,
) -> None:
    identifier, selected = settings.identifier, settings.runtime
    if source_evidence is not None:
        deadline = time.monotonic() + 10
        while not site_fpm_idle(identifier, source, source_evidence):
            if time.monotonic() >= deadline:
                raise ValueError("Source post-response or unaccounted work remains active.")
            time.sleep(0.05)
        current = admission.haproxy_state(settings)
        if (
            current["process"] != before["proxy"]["process"]
            or current["selection"] != selected
            or not common.same_site_lock(descriptor, identifier)
        ):
            raise ValueError("The authenticated admission boundary changed before cleanup.")
        if current["errors"] != before["proxy"]["errors"]:
            raise ValueError("Serving errors occurred during the transition; preserve source.")
        remove_stopped_php(php_settings(identifier, before, source))
    elif (source_php_path(identifier, source)).is_symlink() or (
        source_php_path(identifier, source)
    ).exists():
        remove_stopped_php(php_settings(identifier, before, source))


def switch_php(document: dict[str, object]) -> None:
    identifier, selected = str(document["identifier"]), str(document["selection"])
    common.stage("preflight")
    descriptor: int | None = None
    changed = False
    try:
        descriptor = common.open_site_lock(identifier)
        before = php_state(identifier)
        if (
            before["digest"] != document["precondition_digest"]
            or before["profiles"].get(selected) != document["path"]
        ):
            common.result("refused", "precondition")
            return
        if missing_php_modules(before, selected):
            common.result("refused", "precondition")
            return
        settings = php_settings(identifier, before, selected)
        source = "php85" if selected == "php84" else "php84"
        changed = True
        source_evidence = start_target_php(settings, before, source)
        select_target_php(settings, before, source)
        finish_source_php(settings, before, source, source_evidence, descriptor)
        common.stage("commands")
        for name in ("php", "composer", "wp"):
            path = pathlib.Path(settings.directory) / "bin" / name
            replace_php_wrapper(path, common.wrapper(settings, name))
        common.stage("verify")
        final = php_state(identifier)
        if (
            not final["complete"]
            or final["proxy"]["selection"] != selected
            or not common.same_site_lock(descriptor, identifier)
        ):
            raise ValueError("The site runtime transition did not verify.")
        common.verify_readiness(php_settings(identifier, final, selected))
        common.result("succeeded")
    except BlockingIOError:
        common.result("lock_busy")
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        sys.stderr.write(
            "PHP transition stopped (" + type(error).__name__ + "): " + str(error)[:500] + "\n"
        )
        common.result(
            "partial" if changed else "refused", "runtime_config" if changed else "evidence"
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)
