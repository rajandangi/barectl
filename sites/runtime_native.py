"""An exact pool/router replacement inside the shared transient-unit admission."""

import hashlib
import json
import shlex
from dataclasses import dataclass

from bootstrap import native as bootstrap_native
from bootstrap import runtime_native as default_native

from . import native
from .convention import (
    PROBE_TOKEN,
    Application,
    SitePaths,
    recognize_pool,
    recognize_site,
    render_pool,
    render_site,
)


@dataclass(frozen=True)
class Switch:
    identifier: str
    old_branch: str
    branch: str
    old_revision: int
    old_site: str
    new_site: str
    old_pool: str
    new_pool: str
    token: str
    database_engine: str = ""


def _check(change: Switch) -> None:
    old = recognize_site(change.identifier, change.old_site)
    if (
        old is None
        or old.application is Application.WORDPRESS_GATE
        or change.branch not in ("8.3", "8.4", "8.5")
    ):
        raise ValueError("The runtime switch is not a supported installed convention site.")
    SitePaths(change.identifier, change.old_branch, revision=change.old_revision)
    SitePaths(change.identifier, change.branch, revision=4)
    if (
        old.revision != change.old_revision
        or (old.php_version and old.php_version != change.old_branch)
        or not recognize_pool(change.identifier, change.old_pool, php_version=old.php_version)
        or change.new_pool != render_pool(change.identifier, php_version=change.branch)
        or change.new_site
        != render_site(
            change.identifier,
            old.names,
            ipv6=old.ipv6,
            stage=old.stage,
            php_version=change.branch,
            application=old.application,
            canonical=old.canonical,
        )
        or not PROBE_TOKEN.fullmatch(change.token)
        or change.database_engine not in ("", "mariadb", "postgresql")
        or change.branch == change.old_branch
    ):
        raise ValueError("The runtime replacement differs from the exact convention.")


_PROGRAM = r"""
import grp, hashlib, json, os, pwd, stat, subprocess, sys, time

c = json.loads(sys.argv[1])
suffix = sys.argv[2]
if len(suffix) != 32 or any(x not in "0123456789abcdef" for x in suffix):
    raise ValueError("invalid unit suffix")


current_phase = ""
process_exit = None
probe_result = {}


def mark(phase: str) -> None:
    global current_phase, process_exit
    current_phase = phase
    process_exit = None
    probe_result.clear()


def diagnostic(kind: str, error: BaseException) -> None:
    fields = [
        "PHP switch diagnostic", kind, "phase=" + current_phase,
        "exception=" + type(error).__name__,
    ]
    if process_exit is not None:
        fields.append("exit=" + str(process_exit))
    fields.extend(role + " " + result for role, result in probe_result.items())
    print(" ".join(fields))


def command(argv: list[str], phase: str) -> bool:
    global process_exit
    mark(phase)
    p = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
    )
    process_exit = p.returncode
    return p.returncode == 0


def read(path: str) -> tuple[bytes, tuple[int, int]]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if (
            not stat.S_ISREG(s.st_mode)
            or s.st_uid
            or s.st_gid
            or s.st_mode & 0o022
            or s.st_nlink != 1
            or s.st_size > 8192
        ):
            raise ValueError("changed native configuration metadata")
        return os.read(fd, 8193), (s.st_dev, s.st_ino)
    finally:
        os.close(fd)


def safe_directory(path: str) -> None:
    s = os.lstat(path)
    owner = (
        (pwd.getpwnam("www-data").pw_uid, grp.getgrnam("www-data").gr_gid)
        if path == "/run/php"
        else (0, 0)
    )
    if not stat.S_ISDIR(s.st_mode) or (s.st_uid, s.st_gid) != owner or s.st_mode & 0o022:
        raise ValueError("unsafe native configuration directory")


def stage(path: str, data: bytes, mode: int = 0o644) -> None:
    safe_directory(os.path.dirname(path))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("native staging write incomplete")
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def replace(path: str, expected: bytes, data: bytes) -> None:
    before, identity = read(path)
    if before != expected:
        raise ValueError("changed native configuration bytes")
    temporary = os.path.join(
        os.path.dirname(path), "." + c["identifier"] + "." + suffix + ".runtime"
    )
    stage(temporary, data)
    current, current_identity = read(path)
    if current != expected or current_identity != identity:
        raise ValueError("native configuration changed before publication")
    os.replace(temporary, path)


oldpool = c["oldpool"]
newpool = c["newpool"]
site = c["site"]
oldsite = c["old_site"].encode()
newsite = c["new_site"].encode()
oldcontent = c["old_pool"].encode()
newcontent = c["new_pool"].encode()
for path in c["ancestors"]:
    safe_directory(path)
if read(site)[0] != oldsite or read(oldpool)[0] != oldcontent or os.path.lexists(newpool):
    sys.exit(15)
if os.readlink(c["link"]) != site:
    sys.exit(15)
# Recovery preimages use the same ordinary Nginx backup convention as TLS changes.
backup_dir = "/var/backups/nginx"
if not os.path.exists(backup_dir):
    safe_directory("/var/backups")
    os.mkdir(backup_dir, 0o700)
safe_directory(backup_dir)
stage(backup_dir + "/" + c["identifier"] + ".conf." + suffix, oldsite, 0o600)
account = pwd.getpwnam("s" + c["identifier"])
probe = c["public"] + "/probe-" + c["token"] + ".php"
anchor = c["boundary"] + "/.probe-" + c["token"] + "." + suffix + ".anchor"
database_probe = ""
principal = "s" + c["identifier"]
if c["database_engine"] == "mariadb":
    database_probe = (
        '$p=new PDO("mysql:unix_socket=/run/mysqld/mysqld.sock;dbname='
        + principal + ';charset=utf8mb4","' + principal + '");'
        + 'echo " ".(int)($p->query("SELECT CURRENT_USER()")->fetchColumn()==="'
        + principal + '@localhost");'
    )
elif c["database_engine"] == "postgresql":
    database_probe = (
        '$p=new PDO("pgsql:host=/var/run/postgresql;dbname='
        + principal + ';user=' + principal + '");'
        + 'echo " ".(int)($p->query("SELECT CURRENT_USER")->fetchColumn()==="'
        + principal + '");'
    )
probe_text = (
    "<?php echo 'runtime-"
    + c["token"]
    + " '.PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION.' '.posix_geteuid().' '.posix_getegid();"
    + database_probe
).encode()
stage(anchor, probe_text, 0o640)
os.chown(anchor, 0, account.pw_gid)
probe_identity = os.stat(anchor)
os.link(anchor, probe, follow_symlinks=False)


def probe_owned() -> None:
    for path in (probe, anchor):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            state = os.fstat(fd)
            if (
                not stat.S_ISREG(state.st_mode)
                or (state.st_dev, state.st_ino) != (probe_identity.st_dev, probe_identity.st_ino)
                or state.st_uid
                or state.st_gid != account.pw_gid
                or state.st_mode & 0o777 != 0o640
                or state.st_nlink != 2
                or os.read(fd, 8193) != probe_text
            ):
                raise ValueError("temporary runtime probe changed")
        finally:
            os.close(fd)


def served(branch: str, phase: str) -> bool:
    mark(phase)
    wanted = (
        "runtime-"
        + c["token"]
        + " "
        + branch
        + " "
        + str(account.pw_uid)
        + " "
        + str(account.pw_gid)
    ).encode()
    if c["database_engine"]:
        wanted += b" 1"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        probe_result.clear()
        probe_owned()
        valid = True
        names = (c["canonical"],) if c["wordpress"] else c["names"]
        for name in names:
            scheme, port = ("https", 443) if c["https"] else ("http", 80)
            url = scheme + "://" + name + "/probe-" + c["token"] + ".php"
            probe_result["probe"] = "unavailable"
            p = subprocess.run(
                [
                    "/usr/bin/curl",
                    "--silent",
                    "--fail",
                    "--max-time",
                    "1",
                    "--max-filesize",
                    "256",
                    "--resolve",
                    name + ":" + str(port) + ":127.0.0.1",
                    url,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=2,
                env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
            )
            probe_result["probe"] = (
                "exit=" + str(p.returncode) + " bytes=" + str(len(p.stdout))
                + " identity=" + str(p.stdout == wanted).lower()
            )
            if p.returncode != 0 or p.stdout != wanted:
                valid = False
        if valid and c["wordpress"]:
            for path in ("/", "/wp-login.php"):
                role = "home" if path == "/" else "login"
                probe_result[role] = "unavailable"
                p = subprocess.run([
                    "/usr/bin/curl", "--silent", "--max-time", "10",
                    "--max-filesize", "4194304", "--output", "/dev/null",
                    "--write-out", "%{http_code}", "--resolve",
                    c["canonical"] + ":443:127.0.0.1",
                    "https://" + c["canonical"] + path,
                ], stdin=subprocess.DEVNULL, capture_output=True, timeout=12,
                   env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
                status = (
                    p.stdout.decode("ascii")
                    if len(p.stdout) == 3 and p.stdout.isdigit()
                    else "invalid"
                )
                probe_result[role] = "exit=" + str(p.returncode) + " http=" + status
                if p.returncode or p.stdout != b"200":
                    valid = False
        if valid:
            return True
        time.sleep(0.1)
    return False


def cleanup_probe() -> None:
    probe_owned()
    os.unlink(probe)
    os.unlink(anchor)


new_created = False
site_changed = False
old_removed = False
try:
    mark("target-pool-staging")
    stage(newpool, newcontent)
    new_created = True
    if not command(["/usr/sbin/php-fpm" + c["branch"], "-t"], "target-fpm-check"):
        raise ValueError("target FPM configuration rejected")
    if not command(["/usr/bin/systemctl", "reload", "php" + c["branch"] + "-fpm.service"],
                   "target-fpm-reload"):
        raise ValueError("target FPM reload refused")
    mark("router-publication")
    replace(site, oldsite, newsite)
    site_changed = True
    if not command(["/usr/sbin/nginx", "-t", "-q"], "target-nginx-check"):
        raise ValueError("Nginx replacement rejected")
    if not command(["/usr/bin/systemctl", "reload", "nginx.service"], "target-nginx-reload"):
        raise ValueError("Nginx reload refused")
    if not served(c["branch"], "target-serving"):
        raise ValueError("selected runtime did not serve with the site identity")
    mark("old-pool-withdrawal")
    if read(oldpool)[0] != oldcontent:
        raise ValueError("old pool changed before withdrawal")
    os.unlink(oldpool)
    old_removed = True
    if not command(["/usr/sbin/php-fpm" + c["old_branch"], "-t"], "old-fpm-check") or not command(
        ["/usr/bin/systemctl", "reload", "php" + c["old_branch"] + "-fpm.service"], "old-fpm-reload"
    ):
        raise ValueError("old FPM pool withdrawal refused")
except (OSError, ValueError, subprocess.SubprocessError) as error:
    diagnostic("apply", error)
    try:
        if old_removed:
            mark("restore-old-pool")
            stage(oldpool, oldcontent)
        if site_changed:
            mark("restore-router")
            replace(site, newsite, oldsite)
        if new_created:
            mark("restore-target-pool-removal")
            if read(newpool)[0] != newcontent:
                raise ValueError("target pool changed during recovery")
            os.unlink(newpool)
        if (
            not command(["/usr/sbin/php-fpm" + c["old_branch"], "-t"], "restored-old-fpm-check")
            or not command(["/usr/sbin/php-fpm" + c["branch"], "-t"], "restored-target-fpm-check")
            or not command(["/usr/sbin/nginx", "-t", "-q"], "restored-nginx-check")
        ):
            raise ValueError("restored configuration rejected")
        if (
            not command(["/usr/bin/systemctl", "reload", "php" + c["old_branch"] + "-fpm.service"],
                        "restored-old-fpm-reload")
            or not command(["/usr/bin/systemctl", "reload", "php" + c["branch"] + "-fpm.service"],
                           "restored-target-fpm-reload")
            or not command(["/usr/bin/systemctl", "reload", "nginx.service"],
                           "restored-nginx-reload")
        ):
            raise ValueError("restored services did not reload")
        if not served(c["old_branch"], "restored-serving"):
            raise ValueError("restored site runtime did not serve")
        mark("restored-probe-cleanup")
        cleanup_probe()
        print("PHP switch refused; original pool and router restored.")
        sys.exit(41)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        diagnostic("restore", error)
        print("PHP switch is partial; inspect the retained native preimages and service state.")
        sys.exit(40)
try:
    mark("probe-cleanup")
    cleanup_probe()
except (OSError, ValueError) as error:
    diagnostic("cleanup", error)
    print("PHP switch is partial; temporary probe cleanup could not be proven.")
    sys.exit(40)
print("PHP pool and router switched.")
"""


def body(
    change: Switch,
    *,
    default_digest: str,
    site_digest: str,
    binding: tuple[tuple[str, str], ...] = (),
    wordpress_digest: str = "",
) -> str:
    _check(change)
    old = SitePaths(change.identifier, change.old_branch, revision=change.old_revision)
    new = SitePaths(change.identifier, change.branch, revision=4)
    recognized = recognize_site(change.identifier, change.old_site)
    if recognized is None:
        raise ValueError("The original site is unrecognized.")
    data = {
        "database_engine": change.database_engine,
        "token": change.token,
        "public": new.public,
        "boundary": new.boundary,
        "names": list(recognized.names),
        "https": recognized.stage.activated,
        "canonical": recognized.canonical_name,
        "wordpress": recognized.application is Application.WORDPRESS,
        "identifier": change.identifier,
        "old_branch": change.old_branch,
        "branch": change.branch,
        "old_site": change.old_site,
        "new_site": change.new_site,
        "old_pool": change.old_pool,
        "new_pool": change.new_pool,
        "oldpool": old.pool,
        "newpool": new.pool,
        "site": old.source,
        "link": old.link,
        "ancestors": sorted({*native.ancestors(old), *native.ancestors(new)}),
    }
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"))
    program = shlex.join(["/usr/bin/python3", "-I", "-c", _PROGRAM, encoded]) + ' "$suffix"'
    conditions = (
        (default_native.DIGEST, default_digest),
        (native.site_digest(old), site_digest),
        *binding,
    )
    helpers: tuple[str, ...] = ()
    if recognized.application.wordpress:
        from wordpress.inspection_native import state_script

        helpers = ("runtime_wordpress_state() { " + state_script(change.identifier) + "; }",)
        conditions = (*conditions, ("runtime_wordpress_state | sha256sum", wordpress_digest))
    elif wordpress_digest:
        raise ValueError("A generic switch cannot carry WordPress state.")
    return "; ".join((*helpers, *bootstrap_native.digest_preconditions(conditions), program))


def payload(
    unit: str,
    boot: str,
    deadline: int,
    change: Switch,
    *,
    default_digest: str,
    site_digest: str,
    body_sha256: str,
    binding: tuple[tuple[str, str], ...] = (),
    wordpress_digest: str = "",
) -> str:
    text = body(
        change,
        default_digest=default_digest,
        site_digest=site_digest,
        binding=binding,
        wordpress_digest=wordpress_digest,
    )
    if hashlib.sha256(text.encode()).hexdigest() != body_sha256:
        raise ValueError("The runtime body differs from the reviewed digest.")
    steps = [
        *bootstrap_native.admission(unit, boot, deadline),
        f"suffix={unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix('.service')}",
        *bootstrap_native.staged(text),
    ]
    return "; ".join(steps)
