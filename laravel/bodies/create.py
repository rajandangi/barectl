"""The native body that creates one Laravel site (Phase B #382).

Executed on the target as root by the change engine's staged payload, which already holds
the mutation lock and admitted the review. It builds the site exactly as the plain create
does, then adds Laravel's shared state: the private environment with a generated ``APP_KEY``,
the deploy key and trusted repository host keys, a first release whose Git metadata carries
the reviewed repository and branch, and the site's own database (composed from #379's body).
Nothing it does is undone.

This module is also a complete Python module for the fast layer: it imports the site and
Laravel convention helpers it uses. When a body is assembled, those imports are stripped and
the helpers are inlined from ``sites.observation``'s ``COMMON_SOURCE`` and
``laravel.bodies.common`` (the same pattern the Deploy and Roll back bodies use).
"""

import base64
import gzip
import json
import os
import pathlib
import pwd
import subprocess
import sys
from types import SimpleNamespace

from laravel.bodies.common import (
    classify,
    laravel_paths,
    link_shared,
    switch_current,
    user_command,
)
from sites.bodies.common import (
    caddy_file,
    configure_pool,
    create_account,
    create_layout,
    identity_name_exists,
    pool_file,
    publish_caddy,
    result,
    runtime_admission,
    setting,
    stage,
    validate_candidate,
    validate_pool_candidate,
    verify_http,
    write_new,
)

# The ``databases.bodies.site`` source, injected at assembly time. It is executed in an
# isolated namespace so its ``run``/``result``/``stage`` helpers do not shadow the site
# convention's own, exactly the way the site-database change runs it.
DATABASE_BODY = ""

# The placeholder ``artisan`` published before the first Deploy, so the site is a recognized
# Laravel application whose Git metadata carries the repository and branch Deploy reads.
ARTISAN_PLACEHOLDER = """#!/usr/bin/env php
<?php

// Barectl publishes this placeholder so the site is a recognized Laravel application
// before its first Deploy. Deploy replaces it with the repository's own ``artisan``.
"""


def private_path(settings: SimpleNamespace, name: str) -> pathlib.Path:
    _, _, _, private = laravel_paths(str(settings.identifier))
    return private / name


def _own(path: pathlib.Path, uid: int, gid: int, mode: int) -> None:
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def write_private(path: pathlib.Path, contents: str, uid: int, gid: int, mode: int = 0o600) -> None:
    """Create a site-owned private file, never following or replacing an existing entry."""
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "w") as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())
        os.fchown(output.fileno(), uid, gid)
        os.fchmod(output.fileno(), mode)


def _private_directory(settings: SimpleNamespace, name: str, uid: int, gid: int) -> pathlib.Path:
    target = private_path(settings, name)
    if not target.exists():
        target.mkdir(mode=0o700)
    _own(target, uid, gid, 0o700)
    return target


def laravel_state(
    settings: SimpleNamespace, account: pwd.struct_passwd, document: dict[str, object]
) -> None:
    """Add Laravel's shared state, the private environment and a first recognizable release."""
    uid, gid = int(account.pw_uid), int(account.pw_gid)
    home = pathlib.Path(str(settings.directory))
    # Composer pings packagist after an install unless its own configuration disables the
    # notification; a managed server reaches no host but the repository (Phase B #259).
    for directory in (home / ".config", home / ".config" / "composer"):
        if not directory.exists():
            directory.mkdir(mode=0o700)
        _own(directory, uid, gid, 0o700)
    write_private(
        home / ".config" / "composer" / "config.json",
        "{\n"
        '    "config": {\n'
        '        "notify-on-install": false,\n'
        '        "audit": {\n'
        '            "abandoned": "ignore"\n'
        "        }\n"
        "    }\n"
        "}\n",
        uid,
        gid,
    )
    storage = _private_directory(settings, "storage", uid, gid)
    # Laravel's shared storage needs its runtime directories to exist: the default view
    # configuration resolves ``storage/framework/views`` with ``realpath``, which is false
    # on a missing directory, and every release links this one shared tree.
    for relative in (
        "app/public",
        "framework/cache/data",
        "framework/sessions",
        "framework/views",
        "logs",
    ):
        directory = storage / relative
        if not directory.exists():
            directory.mkdir(mode=0o700, parents=True)
        _own(directory, uid, gid, 0o700)
    _private_directory(settings, "cache", uid, gid)
    key = "base64:" + base64.b64encode(os.urandom(32)).decode()
    write_private(
        private_path(settings, "laravel.env"),
        str(document["environment"]).replace("APP_KEY={{generated}}", "APP_KEY=" + key),
        uid,
        gid,
    )
    if document.get("ssh"):
        deploy_key = private_path(settings, "deploy_key")
        user_command(
            settings,
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(deploy_key)],
        )
        _own(deploy_key, uid, gid, 0o600)
        _own(deploy_key.with_name(deploy_key.name + ".pub"), uid, gid, 0o644)
    host_keys = document.get("host_keys")
    if isinstance(host_keys, list) and host_keys:
        write_private(
            private_path(settings, "known_hosts"),
            "".join(str(line) + "\n" for line in host_keys),
            uid,
            gid,
        )
    release = pathlib.Path(str(settings.directory)) / "releases" / str(document["release"])
    subprocess.run(  # noqa: S603 - fixed argv in the site's own release layout
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", str(release)],
        check=True,
        timeout=60,
    )
    _write_release(settings, document, release)
    link_shared(settings, release)
    classify(settings, release)
    switch_current(settings, str(document["release"]))


def _git_config(repository: str) -> str:
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        '[remote "origin"]\n'
        f"\turl = {repository}\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
    )


def _placeholder(settings: SimpleNamespace) -> str:
    return (
        '<?php header("Content-Type: application/json"); echo json_encode(["site"=>"'
        + str(settings.identifier)
        + '","uid"=>posix_geteuid(),"runtime"=>PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION]);\n'
    )


def _write_release(
    settings: SimpleNamespace, document: dict[str, object], release: pathlib.Path
) -> None:
    account = str(settings.account)
    public = release / "public"
    git = release / ".git"
    for directory in (public, git):
        subprocess.run(  # noqa: S603 - fixed argv in the site's own release layout
            ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", str(directory)],
            check=True,
            timeout=60,
        )
    write_new(str(release / "artisan"), ARTISAN_PLACEHOLDER, 0o600, account, account)
    write_new(str(public / "index.php"), _placeholder(settings), 0o600, account, account)
    write_new(str(public / "hello.txt"), "Welcome to your Laravel site.\n", 0o640, account, "caddy")
    write_new(
        str(git / "config"), _git_config(str(document["repository"])), 0o600, account, account
    )
    write_new(
        str(git / "HEAD"),
        "ref: refs/heads/" + str(document["branch"]) + "\n",
        0o600,
        account,
        account,
    )


def database_state(document: dict[str, object]) -> tuple[str, str]:
    """Run #379's own site-database body against this site, in an isolated namespace.

    Returns ``("", "")`` on success, or the result class and reason the create reports.
    """
    namespace: dict[str, object] = {"__name__": "databases.bodies.site"}
    exec(compile(DATABASE_BODY, "databases/bodies/site.py", "exec"), namespace)  # noqa: S102
    publish_probe = namespace["publish_probe"]
    probe = namespace["probe"]
    apply_statements = namespace["apply_statements"]
    prove = namespace["prove"]
    remove_probe = namespace["remove_probe"]
    if not publish_probe(document):  # type: ignore[operator]
        return ("refused", "site_database")
    if probe(document, "pre") != document["expected_pre"]:  # type: ignore[operator]
        return ("refused", "site_database_driver")
    reason = apply_statements(document)  # type: ignore[operator]
    if reason:
        return ("partial", str(reason))
    reason = prove(document)  # type: ignore[operator]
    if reason:
        return ("partial", str(reason))
    if not remove_probe(document):  # type: ignore[operator]
        return ("partial", "site_database_probe")
    return ("", "")


def _create_preflight(document: dict[str, object], settings: SimpleNamespace) -> str:
    """The reviewed native state the create rechecks under the lock, or a refusal reason."""
    identity = document.get("identity")
    if type(identity) is not int:
        return "evidence"
    try:
        before = runtime_admission(document, settings)
    except ValueError, OSError, subprocess.TimeoutExpired:
        return "evidence"
    if (
        before["digest"] != document["precondition_digest"]
        or before["disk_digest"] != document["disk_digest"]
        or before["next_id"] != document["identity"]
        or before["next_proxy_id"] != document["proxy_identity"]
        or settings.identifier in before["current_sites"]
        or pathlib.Path(settings.directory).exists()
        or identity_name_exists(settings.identifier)
    ):
        return "evidence"
    try:
        validate_candidate(settings.identifier, caddy_file(settings))
        validate_pool_candidate(settings, identity, pool_file(settings))
    except ValueError, OSError, subprocess.TimeoutExpired:
        return "evidence"
    return ""


def create_laravel(document: dict[str, object]) -> None:
    names = document.get("names")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        result("refused", "evidence")
        return
    https = document.get("https", True) is not False
    settings = setting(str(document["identifier"]), names, str(document["selection"]), https=https)
    stage("preflight")
    refusal = _create_preflight(document, settings)
    if refusal:
        result("refused", refusal)
        return
    changed = False
    deployment_lock: int | None = None
    try:
        stage("account")
        identity = document.get("identity")
        if type(identity) is not int:
            raise ValueError("Invalid reviewed identity.")
        changed = True
        account = create_account(settings, identity)
        stage("layout")
        deployment_lock = create_layout(settings)
        stage("pool")
        configure_pool(settings, account, int(str(document["proxy_identity"])))
        stage("caddy")
        if not publish_caddy(settings.identifier, caddy_file(settings), None):
            result("partial", "site_caddy")
            return
        stage("laravel")
        laravel_state(settings, account, document)
        stage("database")
        outcome, reason = database_state(document)
        if outcome:
            result(outcome, reason)
            return
        stage("verify")
        verify_http(settings, account.pw_uid, readiness=False)
        result("succeeded")
    except ValueError, OSError, subprocess.TimeoutExpired:
        result("partial" if changed else "refused", "site_create" if changed else "evidence")
    finally:
        if deployment_lock is not None:
            os.close(deployment_lock)


if __name__ == "__main__":
    create_laravel(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
