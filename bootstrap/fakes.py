"""A simulated Ubuntu server's native evidence for plan preparation tests.

``UbuntuServer`` answers every preparation command on a ``discovery.fakes.FakeServer``,
with output in the exact shapes recorded from the disposable acceptance server of its
release: Ubuntu 24.04 (apt 2.8.3, systemd 255) by default, or Ubuntu 26.04 (apt 3.2.0,
systemd 259). Tests change its fields, such as which profiles are installed or which hooks
are configured, and ``answer`` writes the answers. The commands themselves come from
``bootstrap.inspection``; ``PREPARATION_READ_ONLY`` states independently which command
shapes preparation may run.
"""

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar, override

from discovery.fakes import READ_ONLY, DiscoveryTestCase, FakeServer
from discovery.ssh import CommandResult, ConnectionFailed
from servers.models import Server

from . import inspection, native
from .models import Action, ConfigurationPlan, PlanPreparation, Privilege
from .profiles import MARIADB_SOCKET, PROFILES, Profile, profile
from .releases import NOBLE, RESOLUTE, Release

BOOT_ID = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
# Hundredths of a second: 5,000.25 seconds after boot.
UPTIME = "5000.25 19822.11\n"
UPTIME_CENTISECONDS = 500025
SITE = "http://archive.ubuntu.com/ubuntu"
THIRD_PARTY = "https://repository.example/ubuntu"
# The server's clock, as date -u +%s prints it: 2026-09-29 12:00:00 UTC.
CLOCK = "1790683200"
# The addresses the default Nginx site listens on, as ss reports them.
WILDCARDS = ("0.0.0.0", "[::]")  # noqa: S104 - reported addresses, not a bind

# The hook entries' keys as apt-config dump prints them.
_HOOK_KEYS = {
    "dpkg::pre-install-pkgs": "DPkg::Pre-Install-Pkgs::",
    "dpkg::post-invoke": "DPkg::Post-Invoke::",
    "apt::update::post-invoke-success": "APT::Update::Post-Invoke-Success::",
    "apt::update::pre-invoke": "APT::Update::Pre-Invoke::",
    "binary::apt::aptcli::hooks::upgrade": "binary::apt::AptCli::Hooks::Upgrade::",
    "binary::apt::aptcli::hooks::install": "binary::apt::AptCli::Hooks::Install::",
    "dpkg::tools::options::/usr/bin/apt_hook_ubuntu_virt::version": (
        "DPkg::Tools::options::/usr/bin/apt_hook_ubuntu_virt::Version"
    ),
}


def baseline_hooks(release: Release) -> tuple[tuple[str, str], ...]:
    """The release's tested hook baseline, as apt-config dump prints it."""
    return tuple((_HOOK_KEYS[name], value) for (name, value) in release.hooks)


_SETTINGS = (
    ("APT", ""),
    ("APT::Architecture", "amd64"),
    ("APT::Install-Recommends", "1"),
    ("Acquire::AllowInsecureRepositories", "0"),
    ("Acquire::AllowDowngradeToInsecureRepositories", "0"),
    ("Dir::Bin::dpkg", "/usr/bin/dpkg"),
    # A secret-looking value that must never be stored or shown.
    ("Acquire::http::Proxy", "http://proxyuser:hunter2@proxy.internal:3128"),
)

type Package = tuple[str, str, str, str]


@dataclass(frozen=True)
class Packaging:
    """What a release's packages look like on the disposable acceptance server."""

    release: Release
    os_release: str
    # dpkg-query's versions of apt, dpkg and systemd.
    tools: str
    needrestart: str
    nginx_version: str
    # The dependencies APT adds to nginx on a server without them, in the simulation's
    # order, as (name, version, architecture, origins).
    nginx_dependencies: tuple[Package, ...]
    nginx_conffiles: dict[str, str]
    php_version: str
    # The PHP packages the profile installs, in the simulation's order, the roots last.
    php_packages: tuple[Package, ...]
    php_conffiles: dict[str, str]
    # The files ucf registers under the PHP trees, by path.
    php_ucf: dict[str, str]
    # The module the SAPIs' conf.d link to, such as "opcache".
    php_module: str
    mariadb_version: str
    # The MariaDB server's closure, in the simulation's order, the root last.
    mariadb_packages: tuple[Package, ...]
    # The configuration files each package installs under /etc/mysql, by package.
    mariadb_conffiles: dict[str, dict[str, str]]

    @property
    def updates(self) -> str:
        """The origins APT names for a version in both the updates and security suites."""
        _, updates, security = self.release.suites
        version = self.release.version
        return f"Ubuntu:{version}/{updates}, Ubuntu:{version}/{security}"

    @property
    def nginx(self) -> Profile:
        return profile(self.release, Action.NGINX)

    @property
    def php(self) -> Profile:
        return profile(self.release, Action.PHP)

    @property
    def mariadb(self) -> Profile:
        return profile(self.release, Action.MARIADB)


_NOBLE_UPDATES = "Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security"
_NOBLE_PHP = "8.3.6-0ubuntu0.24.04.11"
_NOBLE_MARIADB = "1:10.11.14-0ubuntu0.24.04.1"
_MYSQL_COMMON = {
    "/etc/mysql/conf.d/mysql.cnf": "61e0993270966cc6bc96b46c01ade21f",
    "/etc/mysql/conf.d/mysqldump.cnf": "20890decb4486ce539753193908fb356",
    "/etc/mysql/my.cnf.fallback": "cfe2bc1819d5e200eca8ca6912f714af",
}
NOBLE_PACKAGING = Packaging(
    release=NOBLE,
    os_release=(
        'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
        'VERSION="24.04.5 LTS (Noble Numbat)"\nID=ubuntu\nID_LIKE=debian\n'
    ),
    tools="apt\t2.8.3\ndpkg\t1.22.6ubuntu6.6\nsystemd\t255.4-1ubuntu8.17\n",
    needrestart="3.6-7ubuntu4.5",
    nginx_version="1.24.0-2ubuntu7.18",
    nginx_dependencies=(
        ("libelf1t64", "0.190-1.1ubuntu0.1", "amd64", _NOBLE_UPDATES),
        ("libbpf1", "1:1.3.0-2build2", "amd64", "Ubuntu:24.04/noble"),
        ("iproute2", "6.1.0-1ubuntu6.4", "amd64", "Ubuntu:24.04/noble-updates"),
    ),
    nginx_conffiles={
        "/etc/nginx/fastcgi.conf": "74e91892a9e591cde6d65c3e8e7e5fb2",
        "/etc/nginx/mime.types": "96fd3f507b3a4fe666fcb0bb0042f428",
        "/etc/nginx/nginx.conf": "e5398edc0b51497dba606859fb13a86e",
        "/etc/nginx/sites-available/default": "f1f26aef86f90a484f3a2f46ccc46ff6",
        "/etc/nginx/snippets/fastcgi-php.conf": "828e5bd1f3de7b3ef0e6856598b2a8c0",
    },
    php_version=_NOBLE_PHP,
    php_packages=(
        ("php-common", "2:93ubuntu2", "all", "Ubuntu:24.04/noble"),
        ("php8.3-common", _NOBLE_PHP, "amd64", _NOBLE_UPDATES),
        ("php8.3-opcache", _NOBLE_PHP, "amd64", _NOBLE_UPDATES),
        ("php8.3-readline", _NOBLE_PHP, "amd64", _NOBLE_UPDATES),
        ("php8.3-cli", _NOBLE_PHP, "amd64", _NOBLE_UPDATES),
        ("php8.3-fpm", _NOBLE_PHP, "amd64", _NOBLE_UPDATES),
    ),
    php_conffiles={
        "/etc/php/8.3/fpm/php-fpm.conf": "696fcb228ad0e29f57cdd2082eb41fac",
        "/etc/php/8.3/fpm/pool.d/www.conf": "6204554fd51b0d45f12e2f2b5b62e377",
    },
    php_ucf={
        "/etc/php/8.3/fpm/php.ini": "75451050d77c02f5b29da8360395a9dd",
        "/etc/php/8.3/cli/php.ini": "726c33e11795235b71f7367d79eb8744",
        "/etc/php/8.3/mods-available/opcache.ini": "5454a910708937435d02de816081a39c",
        "/etc/php/8.3/mods-available/pdo.ini": "2bcf2cd02149a7b3118f9a8ed7cfe1b3",
    },
    php_module="opcache",
    mariadb_version=_NOBLE_MARIADB,
    mariadb_packages=(
        ("rsync", "3.2.7-1ubuntu1.5", "amd64", _NOBLE_UPDATES),
        ("galera-4", "26.4.16-2build4", "amd64", "Ubuntu:24.04/noble"),
        ("libmpfr6", "4.2.1-1build1.1", "amd64", "Ubuntu:24.04/noble-updates"),
        ("libsigsegv2", "2.14-1ubuntu2", "amd64", "Ubuntu:24.04/noble"),
        ("gawk", "1:5.2.1-2ubuntu0.1", "amd64", _NOBLE_UPDATES),
        ("mysql-common", "5.8+1.1.0build1", "all", "Ubuntu:24.04/noble"),
        ("mariadb-common", _NOBLE_MARIADB, "all", "Ubuntu:24.04/noble-updates"),
        ("libdbi-perl", "1.643-4ubuntu0.3", "amd64", _NOBLE_UPDATES),
        ("libtirpc-common", "1.3.4+ds-1.1build1", "all", "Ubuntu:24.04/noble"),
        ("libtirpc3t64", "1.3.4+ds-1.1build1", "amd64", "Ubuntu:24.04/noble"),
        ("lsof", "4.95.0-1build3", "amd64", "Ubuntu:24.04/noble"),
        ("libconfig-inifiles-perl", "3.000003-2ubuntu0.1", "all", _NOBLE_UPDATES),
        ("libmariadb3", _NOBLE_MARIADB, "amd64", "Ubuntu:24.04/noble-updates"),
        ("libncurses6", "6.4+20240113-1ubuntu2.2", "amd64", _NOBLE_UPDATES),
        ("mariadb-client-core", _NOBLE_MARIADB, "amd64", "Ubuntu:24.04/noble-updates"),
        ("mariadb-client", _NOBLE_MARIADB, "amd64", "Ubuntu:24.04/noble-updates"),
        ("libnuma1", "2.0.18-1ubuntu0.24.04.1", "amd64", "Ubuntu:24.04/noble-updates"),
        ("liburing2", "2.5-1build1", "amd64", "Ubuntu:24.04/noble"),
        ("mariadb-server-core", _NOBLE_MARIADB, "amd64", "Ubuntu:24.04/noble-updates"),
        ("socat", "1.8.0.0-4ubuntu0.1", "amd64", _NOBLE_UPDATES),
        ("mariadb-server", _NOBLE_MARIADB, "amd64", "Ubuntu:24.04/noble-updates"),
    ),
    mariadb_conffiles={
        "mariadb-client": {
            "/etc/mysql/mariadb.conf.d/50-client.cnf": "a8028d231dad4d2658bfd8b0db11f85e",
            "/etc/mysql/mariadb.conf.d/50-mysql-clients.cnf": "2e0e48974b270cb20c2b66aa71f6cd92",
            "/etc/mysql/mariadb.conf.d/60-galera.cnf": "e2f4b79114ba923199ead4b7e94eee70",
        },
        "mariadb-common": {"/etc/mysql/mariadb.cnf": "f78499dd07dccc3238cc15dd937b87bb"},
        "mariadb-server": {
            "/etc/mysql/debian-start": "c08358d02a853b1dda4bcc4a56f5f798",
            "/etc/mysql/mariadb.conf.d/50-mysqld_safe.cnf": "ae130218a23989c3a504c95831610b4b",
            "/etc/mysql/mariadb.conf.d/50-server.cnf": "70a88ac2d5d3483d48c220af7211177d",
        },
        "mysql-common": _MYSQL_COMMON,
    },
)
_RESOLUTE_UPDATES = "Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security"
_RESOLUTE_PHP = "8.5.4-0ubuntu1.3"
_RESOLUTE_MARIADB = "1:11.8.6-5ubuntu0.1"
RESOLUTE_PACKAGING = Packaging(
    release=RESOLUTE,
    os_release=(
        'PRETTY_NAME="Ubuntu 26.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="26.04"\n'
        'VERSION="26.04.1 LTS (Resolute Raccoon)"\nVERSION_CODENAME=resolute\nID=ubuntu\n'
        "ID_LIKE=debian\nUBUNTU_CODENAME=resolute\n"
    ),
    tools="apt\t3.2.0\ndpkg\t1.23.7ubuntu1\nsystemd\t259.5-0ubuntu3.4\n",
    needrestart="3.11-1ubuntu2",
    nginx_version="1.28.3-2ubuntu1.11",
    # Ubuntu 26.04's nginx needs nothing besides nginx-common on a server image.
    nginx_dependencies=(),
    nginx_conffiles={
        "/etc/nginx/fastcgi.conf": "74e91892a9e591cde6d65c3e8e7e5fb2",
        "/etc/nginx/mime.types": "0dee7492b294fcd97e640f478c146c1a",
        "/etc/nginx/nginx.conf": "b152249b4abac9267ab76cafd454f11a",
        "/etc/nginx/sites-available/default": "f1f26aef86f90a484f3a2f46ccc46ff6",
        "/etc/nginx/snippets/fastcgi-php.conf": "828e5bd1f3de7b3ef0e6856598b2a8c0",
    },
    php_version=_RESOLUTE_PHP,
    php_packages=(
        ("php-common", "2:99ubuntu1", "all", "Ubuntu:26.04/resolute"),
        ("php8.5-common", _RESOLUTE_PHP, "amd64", _RESOLUTE_UPDATES),
        ("php8.5-readline", _RESOLUTE_PHP, "amd64", _RESOLUTE_UPDATES),
        ("php8.5-cli", _RESOLUTE_PHP, "amd64", _RESOLUTE_UPDATES),
        ("php8.5-fpm", _RESOLUTE_PHP, "amd64", _RESOLUTE_UPDATES),
    ),
    php_conffiles={
        "/etc/php/8.5/fpm/php-fpm.conf": "818a7ab877650bdd2c358441da5a0161",
        "/etc/php/8.5/fpm/pool.d/www.conf": "4796bb40e6339bc8bd88a51f6a841a6e",
    },
    php_ucf={
        "/etc/php/8.5/fpm/php.ini": "2eabd35db9232ba7ba42d6a8b61d6f04",
        "/etc/php/8.5/cli/php.ini": "3f8a254a4ce36c073aa4921e9135e133",
        "/etc/php/8.5/mods-available/pdo.ini": "2bcf2cd02149a7b3118f9a8ed7cfe1b3",
        "/etc/php/8.5/mods-available/readline.ini": "04d2378963688a881deb69b0441f2a80",
    },
    php_module="pdo",
    mariadb_version=_RESOLUTE_MARIADB,
    mariadb_packages=(
        ("galera-4", "26.4.25-2", "amd64", "Ubuntu:26.04/resolute"),
        ("libmpfr6", "4.2.2-3", "amd64", "Ubuntu:26.04/resolute"),
        ("gawk", "1:5.3.2-1ubuntu1.1", "amd64", _RESOLUTE_UPDATES),
        ("mysql-common", "5.8+1.1.1ubuntu2", "all", "Ubuntu:26.04/resolute"),
        ("mariadb-common", _RESOLUTE_MARIADB, "all", _RESOLUTE_UPDATES),
        ("libdbi-perl", "1.647-1ubuntu0.26.04.3", "amd64", _RESOLUTE_UPDATES),
        ("liblsof0", "4.99.4+dfsg-2build2", "amd64", "Ubuntu:26.04/resolute"),
        ("lsof", "4.99.4+dfsg-2build2", "amd64", "Ubuntu:26.04/resolute"),
        ("libmariadb3", _RESOLUTE_MARIADB, "amd64", _RESOLUTE_UPDATES),
        ("libncurses6", "6.6+20251231-1", "amd64", "Ubuntu:26.04/resolute"),
        ("mariadb-client-core", _RESOLUTE_MARIADB, "amd64", _RESOLUTE_UPDATES),
        ("libpcre2-posix3", "10.46-1build1", "amd64", "Ubuntu:26.04/resolute"),
        ("mariadb-client", _RESOLUTE_MARIADB, "amd64", _RESOLUTE_UPDATES),
        ("libaio1t64", "0.3.113-8build1", "amd64", "Ubuntu:26.04/resolute"),
        ("mariadb-server-core", _RESOLUTE_MARIADB, "amd64", _RESOLUTE_UPDATES),
        ("rsync", "3.4.1+ds1-7ubuntu0.3", "amd64", _RESOLUTE_UPDATES),
        ("socat", "1.8.1.1-1ubuntu0.1", "amd64", _RESOLUTE_UPDATES),
        ("mariadb-server", _RESOLUTE_MARIADB, "amd64", _RESOLUTE_UPDATES),
    ),
    mariadb_conffiles={
        "mariadb-client": {
            "/etc/mysql/mariadb.conf.d/50-client.cnf": "a8028d231dad4d2658bfd8b0db11f85e",
            "/etc/mysql/mariadb.conf.d/50-mariadb-clients.cnf": "4053917ba6f381811d49188c5803bcdf",
            "/etc/mysql/mariadb.conf.d/60-galera.cnf": "9969065baece427d1b78a1777282f06f",
        },
        "mariadb-common": {"/etc/mysql/mariadb.cnf": "f78499dd07dccc3238cc15dd937b87bb"},
        "mariadb-server": {
            "/etc/mysql/debian-start": "648b9666cf224ddfcc4a3ee96f78cf4c",
            "/etc/mysql/mariadb.conf.d/50-mysqld_safe.cnf": "ae130218a23989c3a504c95831610b4b",
            "/etc/mysql/mariadb.conf.d/50-server.cnf": "9ba7b5c021fd42242419cc9e1869d32f",
        },
        "mysql-common": _MYSQL_COMMON,
    },
)
# Ubuntu 24.04's, which most tests use.
OS_RELEASE = NOBLE_PACKAGING.os_release
NGINX_VERSION = NOBLE_PACKAGING.nginx_version
PHP_VERSION = NOBLE_PACKAGING.php_version
UPDATES = NOBLE_PACKAGING.updates
NGINX_DEPENDENCIES = NOBLE_PACKAGING.nginx_dependencies
# The PHP command-line runtime's version report, which verification reads.
PHP_RUNTIME = "php8.3 -v"
MARIADB_RUNTIME = "/usr/sbin/mariadbd --version"

_PROFILES = [each for profiles in PROFILES.values() for each in profiles.values()]
# The MariaDB profile's privileged, read-only administrative check.
_MARIADB_CHECK = PROFILES["24.04"][Action.MARIADB].check.command
# The command shapes preparation may run, stated independently of the inspection module:
# fixed reads of the platform, APT, dpkg, systemd and configuration files, APT's
# simulation, and sudo only to list authorization or for the listening-socket query.
PREPARATION_READ_ONLY = re.compile(
    r"\A(cat /proc/sys/kernel/random/boot_id|cat /proc/uptime|cat /etc/os-release"
    r"|test -d /run/systemd/system|dpkg --print-architecture|id -u|apt-mark showhold"
    r"|cat /var/lib/ucf/hashfile|LC_ALL=C apt-config dump|LC_ALL=C dpkg --audit)\Z"
    r"|\Adpkg-query -W -f='[^']*' ([a-z0-9+. -]+|'php\[0-9\]\*'|('[a-z0-9*\[\]-]+' ?)+)\Z"
    r"|\Aapt-mark showauto [a-z0-9+. :-]+\Z"
    r"|\ALC_ALL=C apt-get -s -o APT::Install-Recommends=0 -o APT::Install-Suggests=0 "
    r"install [a-z0-9+. -]+\Z"
    r"|\ALC_ALL=C apt-get indextargets (--no-release-info )?--format '[^']*' "
    r"'Created-By: Packages'\Z"
    r"|\ALC_ALL=C apt-cache madison [a-z0-9+. -]+\Z"
    r"|\Asudo -n -l /usr/bin/(systemd-run|ss -Hltnp sport = :(80|3306))\Z"
    r"|\A(sudo -n /usr/bin/ss -Hltnp|/usr/bin/ss -Hltnp|ss -Hltn) sport = :(80|3306)\Z"
    r"|\Asystemctl show [a-z0-9.-]+\.service( -p [A-Za-z]+)+\Z"
    r"|\Atest -e /etc/(nginx|mysql|php(/8\.[35](/(fpm|cli|mods-available))?)?)\Z"
    r"|\Atest -e (?P<present>\S+) \|\| test -L (?P=present)\Z"
    r"|\Astat -c '%F %U' -- /(var/lib/(mysql|mariadb|mysql-files)(/mysql)?|var/log/mysql"
    r"|etc/my\.cnf)\Z"
    r"|\A(update-alternatives --query my\.cnf|readlink -f -- /etc/mysql/my\.cnf"
    r"|/usr/sbin/mariadbd --print-defaults)\Z"
    rf"|\A(sudo -n (-l )?)?{re.escape(_MARIADB_CHECK)}\Z"
    r"|\Afind /etc/php(/8\.[35])? -mindepth 1 -maxdepth 1 -printf '%f\\n'\Z"
    r"|\Ass -Hlx src /run/(php/php8\.[35]-fpm|mysqld/mysqld)\.sock\Z"
    r"|\Afind /etc/(nginx|mysql|php/8\.[35]/(fpm|cli|mods-available)) -xdev "
    r"(-printf '%y\\t%p\\t%l\\n'|-type f -exec md5sum -- \{\} \+)\Z"
    r"|\Afind /etc/apt -xdev -type f ! -path '/etc/apt/auth\.conf\*' -exec sha256sum -- \{\} \+\Z"
    r"|\Afind /etc/apt -maxdepth 2 -xdev -type f .* -exec grep -qiE -- '[^']*' \{\} \\; -print\Z"
    r"|\Afind /var/lib/apt/lists -maxdepth 1 -type f -name '\*_InRelease' "
    r"-exec sha256sum -- \{\} \+\Z"
    r"|\Adate -u \+%s; find /var/lib/apt/lists -maxdepth 1 -type f -name '\*_InRelease' "
    r"-exec grep -H -E '\^\(Origin\|Suite\|Valid-Until\):' -- \{\} \+\Z"
    rf"|\A{re.escape(native.APT_DIGEST)}\Z"
    rf"|\A({'|'.join(re.escape(p.revalidation) for p in _PROFILES)})\Z"
)


def _unit(name: str, *, installed: bool, active: str, enabled: str, drop_ins: str) -> str:
    if not installed:
        return (
            f"Id={name}\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            "FragmentPath=\nDropInPaths=\nUnitFileState=\n"
        )
    return (
        f"Id={name}\nLoadState=loaded\nActiveState={active}\n"
        f"SubState={'running' if active == 'active' else 'dead'}\n"
        f"FragmentPath=/usr/lib/systemd/system/{name}\nDropInPaths={drop_ins}\n"
        f"UnitFileState={enabled}\n"
    )


@dataclass
class UbuntuServer:
    """An Ubuntu server as plan preparation reads it. Change fields, then ``answer``."""

    packaging: Packaging = NOBLE_PACKAGING
    # "installed", "absent", or "leftover" (removed with configuration files left).
    nginx: str = "absent"
    php: str = "absent"
    # "root", "sudo" or "none".
    privilege: str = "sudo"
    nginx_active: str = "active"
    nginx_enabled: str = "enabled"
    php_active: str = "active"
    php_enabled: str = "enabled"
    unit_drop_ins: str = ""
    # The APT hooks: the release's tested baseline unless set.
    hooks: list[tuple[str, str]] = field(default_factory=list)
    # The suites with indexes: the release's suites and its backports unless set.
    suites: tuple[str, ...] = ()
    trusted: bool = True
    # A signed third-party source, as a hosting provider adds one, whose Release file names
    # no Origin, and the packages it offers, as (name, version).
    third_party: bool = False
    third_party_trusted: bool = True
    third_party_offers: tuple[tuple[str, str], ...] = ()
    # Packages the release's backports offer, as (name, version).
    backports_offers: tuple[tuple[str, str], ...] = ()
    # The Valid-Until field of every Release file; Ubuntu's archive sets none.
    valid_until: str | None = None
    holds: tuple[str, ...] = ()
    audit: str = ""
    source_overrides: tuple[str, ...] = ()
    # Other processes listening on port 80, by address.
    other_listeners: tuple[str, ...] = ()
    # Extra entries under /etc/nginx or the PHP version's fpm directory, as (path, md5).
    extra_files: dict[str, str] = field(default_factory=dict)
    changed_conffiles: tuple[str, ...] = ()
    # Other PHP releases' packages dpkg knows, as (name, version, status).
    php_releases: tuple[tuple[str, str, str], ...] = ()
    # Entries under /etc/php besides the profile's, such as another release's directory.
    php_entries: tuple[str, ...] = ()
    # Another process listens on the PHP pool's socket.
    socket_listener: bool = False
    # The PHP CLI alone is installed, without FPM.
    php_cli_only: bool = False
    # Installed dependency versions the nginx simulation would upgrade, if any.
    upgrades: tuple[tuple[str, str, str], ...] = ()
    # The archives offering the nginx packages: the release's updates unless set, or
    # another archive such as a PPA.
    nginx_origins: str = ""
    simulation_text: str | None = None
    # Installed packages marked automatically installed: every profile package but the
    # roots unless set.
    automatic: tuple[str, ...] = ()
    # The MariaDB server: "installed", "absent", or "leftover" (removed with its
    # configuration files and /etc/mysql left).
    mariadb: str = "absent"
    mariadb_active: str = "active"
    mariadb_enabled: str = "enabled"
    # The addresses MariaDB listens on at port 3306 while it runs.
    mariadb_addresses: tuple[str, ...] = ("127.0.0.1",)
    # Other processes listening on port 3306, by address.
    database_listeners: tuple[str, ...] = ()
    # Other database servers' packages dpkg knows, as (name, version, status).
    database_conflicts: tuple[tuple[str, str, str], ...] = ()
    # Paths under /var/lib with their type and owner, besides what an installed MariaDB
    # has; an empty value removes one.
    data_paths: dict[str, str] = field(default_factory=dict)
    # The components with Ubuntu indexes.
    components: tuple[str, ...] = ("main", "universe")
    # The my.cnf alternative's mode and value, when not what the packages leave.
    mariadb_alternative: str = ""
    mariadb_alternative_value: str = ""
    # The options mariadbd --print-defaults reports, and the administrative check's output,
    # when not the distribution's.
    mariadb_defaults: str = ""
    mariadb_admin: str = ""
    # The component the release's archive offers a package from, when not main.
    component_offers: dict[str, str] = field(default_factory=dict)
    # Installed packages' versions, when another repository supplied them.
    installed_versions: dict[str, str] = field(default_factory=dict)
    extra: dict[str, CommandResult] = field(default_factory=dict)

    def __post_init__(self) -> None:
        packaging = self.packaging
        release = packaging.release
        self.hooks = self.hooks or list(baseline_hooks(release))
        self.suites = self.suites or (*release.suites, f"{release.codename}-backports")
        self.nginx_origins = self.nginx_origins or packaging.updates
        roots = {*packaging.nginx.roots, *packaging.php.roots, *packaging.mariadb.roots}
        self.automatic = self.automatic or (
            "nginx-common",
            *(name for name, *_ in packaging.php_packages if name not in roots),
            *(name for name, *_ in packaging.nginx_dependencies),
            *(name for name, *_ in packaging.mariadb_packages if name not in roots),
        )

    @property
    def php_release(self) -> str:
        return self.packaging.release.php

    def answer(self, remote: FakeServer) -> None:
        if self._package_query not in remote.answers:
            remote.answers.append(self._package_query)
        results = remote.results
        results.update(self._platform())
        results.update(self._apt())
        results.update(self._packages())
        results.update(self._web())
        results.update(self._mariadb_web())
        results.update(self.extra)

    def _platform(self) -> dict[str, CommandResult]:
        uid = "0\n" if self.privilege == "root" else "1000\n"
        sudo = self.privilege == "sudo"
        return {
            inspection.BOOT_ID: CommandResult(0, f"{BOOT_ID}\n"),
            inspection.UPTIME: CommandResult(0, UPTIME),
            inspection.OS_RELEASE: CommandResult(0, self.packaging.os_release),
            inspection.SYSTEMD: CommandResult(0, ""),
            inspection.ARCHITECTURE: CommandResult(0, "amd64\n"),
            inspection.TOOL_VERSIONS: CommandResult(0, self.packaging.tools),
            inspection.USER_ID: CommandResult(0, uid),
            inspection.SUDO_APPLY: CommandResult(0, "/usr/bin/systemd-run\n")
            if sudo
            else CommandResult(1, ""),
            inspection.sudo_listeners(80): CommandResult(0, "/usr/bin/ss -Hltnp sport = :80\n")
            if sudo
            else CommandResult(1, ""),
            inspection.sudo_listeners(3306): CommandResult(0, "/usr/bin/ss -Hltnp sport = :3306\n")
            if sudo
            else CommandResult(1, ""),
        }

    def _apt(self) -> dict[str, CommandResult]:
        release = self.packaging.release
        codename = release.codename
        trusted = "yes" if self.trusted else "no"
        lines = [f'{key} "{value}";' for key, value in _SETTINGS]
        lines.extend(f'{key} "{value}";' for key, value in self.hooks)
        targets = "".join(
            f"Ubuntu|{suite}|{codename}|{suite}|{trusted}|{component}|amd64|{SITE}\n"
            for suite in self.suites
            for component in self.components
        )
        releases = "".join(
            f"{index:064x}  /var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_{suite}_InRelease\n"
            for index, suite in enumerate(self.suites, start=1)
        )
        validity = [CLOCK]
        for suite in self.suites:
            path = f"/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_{suite}_InRelease"
            validity += [f"{path}:Origin: Ubuntu", f"{path}:Suite: {suite}"]
            if self.valid_until is not None:
                validity.append(f"{path}:Valid-Until: {self.valid_until}")
        configured = [
            f"{SITE}|{suite}|{component}\n"
            for suite in (*release.suites, release.backports)
            for component in ("main", "universe")
        ]
        if self.third_party:
            state = "yes" if self.third_party_trusted else "no"
            targets += (
                f"$(ORIGIN)|{codename}|{codename}|{codename}|{state}|main|amd64|{THIRD_PARTY}\n"
            )
            path = f"/var/lib/apt/lists/repository.example_ubuntu_dists_{codename}_InRelease"
            releases += f"{'f' * 64}  {path}\n"
            validity.append(f"{path}:Suite: {codename}")
            configured.append(f"{THIRD_PARTY}|{codename}|main\n")
        files = (
            f"{'a' * 64}  /etc/apt/sources.list.d/ubuntu.sources\n"
            f"{'b' * 64}  /etc/apt/apt.conf.d/70debconf\n"
        )
        return {
            inspection.APT_CONFIG: CommandResult(0, "\n".join(lines) + "\n"),
            inspection.APT_FILES: CommandResult(0, files),
            inspection.SOURCE_OVERRIDES: CommandResult(
                0, "".join(f"{path}\n" for path in self.source_overrides)
            ),
            inspection.INDEX_TARGETS: CommandResult(0, targets),
            inspection.CONFIGURED_SOURCES: CommandResult(0, "".join(configured)),
            inspection.RELEASES: CommandResult(0, releases),
            inspection.RELEASE_VALIDITY: CommandResult(0, "\n".join(validity) + "\n"),
            native.APT_DIGEST: CommandResult(0, f"{self.apt_digest()}  -\n"),
        }

    def apt_digest(self) -> str:
        """The server's APT digest, which follows its configuration and hooks."""
        lines = [f"{key} {value}" for key, value in (*_SETTINGS, *self.hooks)]
        return hashlib.sha256("\n".join(lines).encode()).hexdigest()

    def _states(self) -> dict[str, str]:
        packaging = self.packaging
        nginx = packaging.nginx_version
        states = {"needrestart": f"needrestart\tall\t{packaging.needrestart}\tii "}
        if self.nginx == "installed":
            states["nginx"] = f"nginx\tamd64\t{nginx}\tii "
            states["nginx-common"] = f"nginx-common\tall\t{nginx}\tii "
            for name, version, arch, _ in packaging.nginx_dependencies:
                states[name] = f"{name}\t{arch}\t{version}\tii "
        elif self.nginx == "leftover":
            states["nginx-common"] = f"nginx-common\tall\t{nginx}\trc "
        if self.php == "installed":
            for name, version, arch, _ in packaging.php_packages:
                if name != f"php{self.php_release}-fpm" or not self.php_cli_only:
                    states[name] = f"{name}\t{arch}\t{version}\tii "
        states.update(self._mariadb_states())
        for name, previous, _ in self.upgrades:
            states[name] = f"{name}\tamd64\t{previous}\tii "
        for hold in self.holds:
            states.setdefault(hold, f"{hold}\t\t\thn ")
        return self._with_versions(states)

    def _with_versions(self, states: dict[str, str]) -> dict[str, str]:
        """``states`` with the versions another repository supplied."""
        for name, version in self.installed_versions.items():
            if name in states:
                package, architecture, _, status = states[name].split("\t")
                states[name] = f"{package}\t{architecture}\t{version}\t{status}"
        return states

    def _mariadb_states(self) -> dict[str, str]:
        packaging = self.packaging
        if self.mariadb == "leftover":
            version = packaging.mariadb_version
            return {"mariadb-server": f"mariadb-server\tamd64\t{version}\trc "}
        if self.mariadb != "installed":
            return {}
        return {
            name: f"{name}\t{arch}\t{version}\tii "
            for name, version, arch, _ in packaging.mariadb_packages
        }

    def _packages(self) -> dict[str, CommandResult]:
        packaging = self.packaging
        fpm, cli = packaging.php.roots
        return {
            inspection.DPKG_AUDIT: CommandResult(0, self.audit),
            inspection.HOLDS: CommandResult(0, "".join(f"{hold}\n" for hold in self.holds)),
            inspection.simulate(["nginx"]): CommandResult(
                0, self.simulation_text or self._nginx_simulation()
            ),
            inspection.simulate([fpm, cli]): CommandResult(0, self._php_simulation()),
            inspection.simulate([fpm]): CommandResult(
                0, _simulation([(n, v, a, o, "") for n, v, a, o in packaging.php_packages[-1:]])
            ),
            packaging.nginx.revalidation: CommandResult(0, f"{self.package_digest()}  -\n"),
            packaging.php.revalidation: CommandResult(0, f"{self.package_digest()}  -\n"),
            inspection.simulate(["mariadb-server"]): CommandResult(0, self._mariadb_simulation()),
            packaging.mariadb.revalidation: CommandResult(0, f"{self.package_digest()}  -\n"),
        }

    def package_digest(self) -> str:
        """The server's package digest, which follows its packages, units and files."""
        state = (
            self.packaging.release.version,
            self.nginx,
            self.php,
            self.nginx_active,
            self.nginx_enabled,
            self.php_active,
            self.php_enabled,
            self.unit_drop_ins,
            self.holds,
            self.audit,
            self.automatic,
            self.other_listeners,
            sorted(self.extra_files.items()),
            self.changed_conffiles,
            self.upgrades,
            self.nginx_origins,
            self.third_party_offers,
            self.backports_offers,
            self.php_releases,
            self.php_entries,
            self.socket_listener,
            self.php_cli_only,
            self.mariadb,
            self.mariadb_active,
            self.mariadb_enabled,
            self.mariadb_addresses,
            self.database_listeners,
            self.database_conflicts,
            sorted(self.data_paths.items()),
            self.components,
            self.mariadb_alternative,
            self.mariadb_alternative_value,
            sorted(self.installed_versions.items()),
        )
        return hashlib.sha256(repr(state).encode()).hexdigest()

    def _marks(self, command: str) -> CommandResult | None:
        """Answer the digests of the sorted automatic marks and ``apt-mark showmanual``."""
        installed = {name for name, line in self._states().items() if line.endswith("ii ")}
        automatic = sorted(installed & set(self.automatic))
        if command == "apt-mark showauto | LC_ALL=C sort | sha256sum":
            return CommandResult(0, f"{_digest(automatic)}  -\n")
        excluded = re.fullmatch(
            r"apt-mark showauto \| grep -vxF ((?:-e \S+ ?)+) \| LC_ALL=C sort \| sha256sum",
            command,
        )
        if excluded:
            others = set(excluded[1].replace("-e ", "").split())
            return CommandResult(0, f"{_digest([n for n in automatic if n not in others])}  -\n")
        if command.startswith("apt-mark showmanual "):
            named = command.removeprefix("apt-mark showmanual ").split()
            manual = [name for name in named if name in installed and name not in automatic]
            return CommandResult(0, "".join(f"{name}\n" for name in manual))
        return None

    def _package_query(self, command: str) -> CommandResult | None:
        """Answer dpkg-query, apt-mark and apt-cache queries for whichever packages they name."""
        marks = self._marks(command) or self._offers(command)
        if marks is not None:
            return marks
        if command == inspection.release_states("php[0-9]*"):
            return CommandResult(0, self._releases())
        if command == inspection.conflict_states(self.packaging.mariadb.conflicts):
            return CommandResult(
                1,
                "".join(
                    f"{name}\tamd64\t{version}\t{status} \n"
                    for name, version, status in self.database_conflicts
                ),
            )
        states = self._states()
        for prefix in (inspection.package_states([]), inspection.automatic_marks([])):
            if not command.startswith(prefix):
                continue
            names = command.removeprefix(prefix).split()
            known = [name for name in names if name in states]
            if prefix == inspection.automatic_marks([]):
                automatic = [name for name in known if name in self.automatic]
                return CommandResult(0, "".join(f"{name}\n" for name in automatic))
            # dpkg-query lists known packages sorted by name, and exits 1 for unknown ones.
            text = "".join(f"{states[name]}\n" for name in sorted(known))
            return CommandResult(0 if len(known) == len(names) else 1, text)
        return None

    def _offers(self, command: str) -> CommandResult | None:
        """Answer apt-cache madison: the simulated versions from the archives the simulation
        names, and the versions the backports and the third-party source offer."""
        prefix = inspection.offers([])
        if not command.startswith(prefix):
            return None
        names = command.removeprefix(prefix).split()
        indexes: list[tuple[str, str, str]] = []
        simulations = (
            self.simulation_text or self._nginx_simulation(),
            self._php_simulation(),
            self._mariadb_simulation(),
        )
        inst = re.compile(r"Inst (\S+) (?:\[\S+\] )?\((\S+) ([^\[]*)\[")
        for text in simulations:
            for match in filter(None, map(inst.match, text.splitlines())):
                for origin in match[3].split(","):
                    archive, _, suite = origin.strip().partition("/")
                    site = SITE if archive.startswith("Ubuntu:") else "https://ppa.example/ubuntu"
                    indexes.append((match[1], match[2], f"{site} {suite}"))
        backports = f"{SITE} {self.packaging.release.backports}"
        indexes += [(name, version, backports) for name, version in self.backports_offers]
        codename = self.packaging.release.codename
        third_party = f"{THIRD_PARTY} {codename}"
        indexes += [(name, version, third_party) for name, version in self.third_party_offers]
        lines = dict.fromkeys(
            f"{name:>10} | {version:>10} | {index}/{self.component_offers.get(name, 'main')} "
            "amd64 Packages\n"
            for name, version, index in indexes
            if name in names
        )
        return CommandResult(0, "".join(lines))

    def _releases(self) -> str:
        """dpkg's answer for every PHP release's packages, as the release query prints it."""
        lines = ["php5.6-common\t\t\tun ", "php8.2-common\t\t\tun "]
        lines += [
            f"{name}\tamd64\t{version}\t{status} " for name, version, status in self.php_releases
        ]
        lines += [
            f"{name}\t{arch}\t{version}\tii "
            for name, version, arch, _ in self.packaging.php_packages
            if name.startswith(f"php{self.php_release}-") and name in self._installed()
        ]
        return "".join(f"{line}\n" for line in sorted(lines))

    def _installed(self) -> set[str]:
        return {name for name, line in self._states().items() if line.endswith("ii ")}

    def _nginx_simulation(self) -> str:
        packaging = self.packaging
        version = packaging.release.version
        updates = f"Ubuntu:{version}/{packaging.release.suites[1]}"
        actions = [
            (name, version, arch, origins, "")
            for name, version, arch, origins in packaging.nginx_dependencies
        ]
        actions.extend(
            (name, new, "amd64", updates, previous) for name, previous, new in self.upgrades
        )
        nginx = packaging.nginx_version
        actions.append(("nginx-common", nginx, "all", self.nginx_origins, ""))
        actions.append(("nginx", nginx, "amd64", self.nginx_origins, ""))
        return _simulation(actions)

    def _php_simulation(self) -> str:
        return _simulation([(n, v, a, o, "") for n, v, a, o in self.packaging.php_packages])

    def _mariadb_simulation(self) -> str:
        return _simulation([(n, v, a, o, "") for n, v, a, o in self.packaging.mariadb_packages])

    def mariadb_data(self) -> dict[str, str]:
        """Each data path's type and owner, as stat reports it; absent paths are omitted."""
        data = self.packaging.mariadb.data
        found: dict[str, str] = {}
        if data is not None and self.mariadb == "installed":
            found = {data.directory: "directory mysql", data.marker: "directory mysql"}
            if self.packaging.release.version == "26.04":
                found["/var/log/mysql"] = "directory mysql"
        found.update(self.data_paths)
        return {path: kind for path, kind in found.items() if kind}

    def _mariadb_web(self) -> dict[str, CommandResult]:
        packaging = self.packaging
        profile = packaging.mariadb
        installed = self.mariadb == "installed"
        running = installed and self.mariadb_active == "active"
        results = {
            inspection.unit_state("mariadb.service"): CommandResult(
                0,
                _unit(
                    "mariadb.service",
                    installed=installed,
                    active=self.mariadb_active,
                    enabled=self.mariadb_enabled,
                    drop_ins=self.unit_drop_ins,
                ),
            ),
            inspection.socket_listeners(MARIADB_SOCKET): CommandResult(
                0,
                f"u_str LISTEN 0      80     {MARIADB_SOCKET} 27509310 * 0\n" if running else "",
            ),
            MARIADB_RUNTIME: CommandResult(
                0,
                f"/usr/sbin/mariadbd  Ver {_upstream(packaging.mariadb_version)}-MariaDB"
                f"-0ubuntu0.24.04.1 for debian-linux-gnu on x86_64 ({packaging.release.name})\n",
            ),
        }
        data = self.mariadb_data()
        for path in profile.paths:
            results[inspection.present(path)] = CommandResult(0 if path in data else 1, "")
            results[inspection.file_type(path)] = CommandResult(
                0 if path in data else 1, f"{data[path]}\n" if path in data else ""
            )
        results.update(self._mysql_configuration(profile, running=running))
        results.update(self._mysql_tree())
        results.update(
            self._listeners_on(
                3306,
                "mariadbd",
                self.mariadb_addresses if running else (),
                self.database_listeners,
            )
        )
        return results

    def _mysql_configuration(self, profile: Profile, *, running: bool) -> dict[str, CommandResult]:
        """The my.cnf alternative, the effective options and the administrative check."""
        installed = self.mariadb == "installed"
        common = installed or "mysql-common" in self._installed()
        mode = self.mariadb_alternative or ("auto" if common else "")
        value = self.mariadb_alternative_value or (
            "/etc/mysql/mariadb.cnf" if installed else "/etc/mysql/my.cnf.fallback"
        )
        query = (
            CommandResult(
                0,
                f"Name: my.cnf\nLink: /etc/mysql/my.cnf\nStatus: {mode}\nBest: {value}\n"
                f"Value: {value}\n\nAlternative: {value}\nPriority: 200\n",
            )
            if mode
            else CommandResult(2, "")
        )
        resolved = value if mode else ("/etc/mysql/my.cnf" if common else "")
        defaults = profile.defaults
        release = self.packaging.release
        options = self.mariadb_defaults or release.mariadb.defaults
        check = profile.check
        admin = CommandResult(0, f"{self.mariadb_admin or check.expected}\n")
        if not running:
            admin = CommandResult(1, "")
        results = {
            inspection.alternative("my.cnf"): query,
            inspection.resolve("/etc/mysql/my.cnf"): CommandResult(
                0 if resolved else 1, f"{resolved}\n" if resolved else ""
            ),
            check.command: admin,
            f"sudo -n {check.command}": admin,
            f"sudo -n -l {check.command}": CommandResult(0 if self.privilege == "sudo" else 1, ""),
        }
        if defaults is not None:
            results[defaults.command] = (
                CommandResult(
                    0,
                    "/usr/sbin/mariadbd would have been started with the following arguments:\n"
                    f"{options} \n",
                )
                if installed
                else CommandResult(127, "")
            )
        return results

    def _mysql_tree(self) -> dict[str, CommandResult]:
        packaging = self.packaging
        installed = self._installed()
        owners = ("mysql-common", "mariadb-common", "mariadb-client", "mariadb-server")
        files: dict[str, str] = {}
        leftover = self.mariadb == "leftover"
        for owner in owners:
            if owner in installed or (leftover and owner == "mariadb-server"):
                files.update(packaging.mariadb_conffiles[owner])
        links = {}
        if "mysql-common" in installed:
            links["/etc/mysql/my.cnf"] = "/etc/alternatives/my.cnf"
        root = self.privilege == "root"
        generated = "/etc/mysql/debian.cnf"
        if self.mariadb in {"installed", "leftover"}:
            files[generated] = packaging.release.mariadb.debian_cnf
        results = self._tree_results("/etc/mysql", files, links, present=bool(files))
        digests = inspection.tree_digests("/etc/mysql")
        if not root and digests in results:
            # md5sum cannot read the file maintainer scripts write for root alone.
            kept = results[digests].stdout.splitlines()
            unread = [line for line in kept if not line.endswith(f"  {generated}")]
            results[digests] = CommandResult(
                1 if len(unread) < len(kept) else 0, "".join(f"{line}\n" for line in unread)
            )
        named = sorted(owner for owner in owners if owner in installed)
        listed = "".join(
            f"{owner}\n"
            + "".join(f" {p} {m}\n" for p, m in packaging.mariadb_conffiles[owner].items())
            for owner in named
        )
        results[inspection.conffiles(named)] = CommandResult(0, listed)
        return results

    def _web(self) -> dict[str, CommandResult]:
        packaging = self.packaging
        php = packaging.php
        (unit,) = php.units
        socket = php.socket or ""
        runtime = php.runtime.command if php.runtime else ""
        results = {
            inspection.unit_state("nginx.service"): CommandResult(
                0,
                _unit(
                    "nginx.service",
                    installed=self.nginx == "installed",
                    active=self.nginx_active,
                    enabled=self.nginx_enabled,
                    drop_ins=self.unit_drop_ins,
                ),
            ),
            inspection.unit_state(unit): CommandResult(
                0,
                _unit(
                    unit,
                    installed=self.php == "installed" and not self.php_cli_only,
                    active=self.php_active,
                    enabled=self.php_enabled,
                    drop_ins=self.unit_drop_ins,
                ),
            ),
            inspection.UCF_HASHES: CommandResult(
                0, "".join(f"{md5}  {path}\n" for path, md5 in packaging.php_ucf.items())
            ),
            inspection.socket_listeners(socket): CommandResult(
                0, "".join(f"{line}\n" for line in self._sockets())
            ),
            runtime: CommandResult(
                0,
                f"PHP {packaging.php_version.split('-')[0]} (cli) "
                "(built: Sep  2 2026 12:56:02) (NTS)\n",
            ),
        }
        results.update(self._php_layout())
        results.update(self._nginx_tree())
        results.update(self._php_trees())
        results.update(self._listeners())
        return results

    def _sockets(self) -> list[str]:
        running = self.php == "installed" and not self.php_cli_only and self.php_active == "active"
        if not (running or self.socket_listener):
            return []
        return [f"u_str LISTEN 0      4096   /run/php/php{self.php_release}-fpm.sock 2247233 * 0"]

    def _php_layout(self) -> dict[str, CommandResult]:
        own = ["cli", "mods-available"] if self.php == "installed" else []
        if own and not self.php_cli_only:
            own.append("fpm")
        top = ([self.php_release] if own else []) + list(self.php_entries)
        results = {}
        for directory, names in (("/etc/php", top), (f"/etc/php/{self.php_release}", own)):
            results[inspection.exists(directory)] = CommandResult(0 if names else 1, "")
            results[inspection.entries(directory)] = CommandResult(
                0, "".join(f"{name}\n" for name in names)
            )
        return results

    def _tree_results(
        self, root: str, files: dict[str, str], links: dict[str, str], present: bool
    ) -> dict[str, CommandResult]:
        if not present:
            return {inspection.exists(root): CommandResult(1, "")}
        files = {
            **files,
            **{p: m for p, m in self.extra_files.items() if p.startswith(f"{root}/")},
        }
        files = {p: ("0" * 32 if p in self.changed_conffiles else m) for p, m in files.items()}
        directories = sorted({root} | {p.rsplit("/", 1)[0] for p in (*files, *links)})
        listing = [f"d\t{path}\t" for path in directories]
        listing += [f"f\t{path}\t" for path in sorted(files)]
        listing += [f"l\t{path}\t{target}" for path, target in sorted(links.items())]
        return {
            inspection.exists(root): CommandResult(0, ""),
            inspection.tree(root): CommandResult(0, "\n".join(listing) + "\n"),
            inspection.tree_digests(root): CommandResult(
                0, "".join(f"{md5}  {path}\n" for path, md5 in sorted(files.items()))
            ),
        }

    def _nginx_tree(self) -> dict[str, CommandResult]:
        conffiles = self.packaging.nginx_conffiles
        results = self._tree_results(
            "/etc/nginx",
            conffiles,
            {"/etc/nginx/sites-enabled/default": "/etc/nginx/sites-available/default"},
            present=self.nginx in {"installed", "leftover"},
        )
        listed = "".join(f" {path} {md5}\n" for path, md5 in conffiles.items())
        results[inspection.conffiles(["nginx-common"])] = CommandResult(
            0, f"nginx-common\n{listed}"
        )
        return results

    def _php_trees(self) -> dict[str, CommandResult]:
        packaging = self.packaging
        php = f"/etc/php/{self.php_release}"
        module = packaging.php_module
        results: dict[str, CommandResult] = {}
        for root in (f"{php}/fpm", f"{php}/cli", f"{php}/mods-available"):
            present = self.php == "installed" and not (self.php_cli_only and root == f"{php}/fpm")
            files = {
                path: md5
                for path, md5 in {**packaging.php_conffiles, **packaging.php_ucf}.items()
                if path.startswith(f"{root}/")
            }
            links = {}
            if root != f"{php}/mods-available":
                links = {f"{root}/conf.d/10-{module}.ini": f"{php}/mods-available/{module}.ini"}
            results.update(self._tree_results(root, files, links, present=present))
        conffiles = "".join(f" {path} {md5}\n" for path, md5 in packaging.php_conffiles.items())
        prefix = f"php{self.php_release}-"
        results[inspection.conffiles([f"{prefix}cli", f"{prefix}common", f"{prefix}fpm"])] = (
            CommandResult(0, f"{prefix}cli\n\n{prefix}common\n\n{prefix}fpm\n{conffiles}")
        )
        return results

    def _listeners(self) -> dict[str, CommandResult]:
        running = self.nginx == "installed" and self.nginx_active == "active"
        return self._listeners_on(80, "nginx", WILDCARDS if running else (), self.other_listeners)

    def _listeners_on(
        self, port: int, process: str, own: tuple[str, ...], others: tuple[str, ...]
    ) -> dict[str, CommandResult]:
        """ss's answers for ``port``: ``process`` on ``own`` addresses, and another
        service on ``others``."""
        attributed = self.privilege in {"root", "sudo"}
        lines = [_listen(address, port, process, attributed) for address in own]
        lines += [_listen(address, port, "apache2", attributed) for address in others]
        privilege = Privilege.ROOT if self.privilege == "root" else Privilege.SUDO
        query = inspection.listeners(port, privilege, attributed=attributed)
        plain = [line.split(" users:", 1)[0] for line in lines]
        return {
            query: CommandResult(0, "".join(f"{line}\n" for line in lines)),
            inspection.listeners(port, Privilege.UNAVAILABLE, attributed=False): CommandResult(
                0, "".join(f"{line}\n" for line in plain)
            ),
        }


def _digest(lines: list[str]) -> str:
    return hashlib.sha256("".join(f"{line}\n" for line in lines).encode()).hexdigest()


def _upstream(version: str) -> str:
    return re.sub(r"-[^-]*\Z", "", re.sub(r"\A[0-9]+:", "", version))


def _listen(address: str, port: int, process: str, attributed: bool) -> str:
    users = f' users:(("{process}",pid=812,fd=5),("{process}",pid=811,fd=5))' if attributed else ""
    return f"LISTEN 0      511    {address}:{port} 0.0.0.0:*{users}"


def _simulation(actions: list[tuple[str, str, str, str, str]]) -> str:
    """APT's simulation output for ``actions``: (name, version, arch, origins, previous)."""
    installs = [a for a in actions if not a[4]]
    upgrades = [a for a in actions if a[4]]
    lines = [
        "NOTE: This is only a simulation!",
        "      apt-get needs root privileges for real execution.",
        "Reading package lists...",
        "Building dependency tree...",
        "Reading state information...",
        "The following NEW packages will be installed:",
        "  " + " ".join(a[0] for a in installs),
        (
            f"{len(upgrades)} upgraded, {len(installs)} newly installed, 0 to remove and 3 "
            "not upgraded."
        ),
    ]
    for name, version, arch, origins, previous in actions:
        before = f"[{previous}] " if previous else ""
        lines.append(f"Inst {name} {before}({version} {origins} [{arch}])")
    for name, version, arch, origins, _ in actions:
        lines.append(f"Conf {name} ({version} {origins} [{arch}])")
    return "\n".join(lines) + "\n"


PLAN_PERMISSIONS = ("view_server", "view_configurationplan", "prepare_configurationplan")


class PreparationTestCase(DiscoveryTestCase):
    """Plan preparation through requests and the worker, against a simulated Ubuntu server
    of ``packaging``'s release, Ubuntu 24.04 unless a test case sets another."""

    packaging: ClassVar[Packaging] = NOBLE_PACKAGING
    ubuntu: UbuntuServer
    server: Server

    @override
    def setUp(self) -> None:
        super().setUp()
        self.ubuntu = UbuntuServer(self.packaging)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    @override
    def assert_read_only(self) -> None:
        for command in self.remote.commands:
            self.assertTrue(
                READ_ONLY.fullmatch(command) or PREPARATION_READ_ONLY.fullmatch(command),
                f"Not a read-only command: {command}",
            )

    def fresh_server(self) -> None:
        """Start again with a new simulated server and no recorded preparations."""
        self.remote.results = FakeServer().results
        self.remote.answers.clear()
        self.ubuntu = UbuntuServer(self.packaging)
        PlanPreparation.objects.all().delete()

    def prepare(
        self, action: str = "nginx", *, perms: tuple[str, ...] = PLAN_PERMISSIONS
    ) -> PlanPreparation:
        """Request a preparation as an operator with ``perms``, run the worker, return it."""
        self.sign_in_with(*perms)
        self.ubuntu.answer(self.remote)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": action})
        self.run_worker()
        return PlanPreparation.objects.latest("queued_at", "pk")

    def plan(self, action: str = "nginx") -> ConfigurationPlan:
        """Prepare ``action`` and return its plan, failing the test without one."""
        preparation = self.prepare(action)
        plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if plan is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return plan

    def reasons(self, plan: ConfigurationPlan) -> list[str]:
        return [refusal.reason for refusal in plan.refusals.all()]


_SUBMITTED_UNIT = re.compile(r"--unit=(barectl-apply-[0-9a-f]{32}\.service)")
# The units a cleanup payload names, each with its reviewed invocation.
_CLEARED = re.compile(r"(barectl-apply-[0-9a-f]{32}\.service):[0-9a-f]{32}")


@dataclass
class NativeUnit:
    """A transient unit the simulated systemd started, as inspection reports it."""

    # Inspections that still find it running before it is terminal.
    running: int
    exit_status: int
    result: str
    exec_main_code: int = 1
    invocation_id: str = "0f" * 16
    # Its processes exit between systemctl show and the control group read, so running
    # reports find the control group already empty.
    exiting: bool = False

    def report(self, name: str) -> str:
        """systemctl show's properties and the populated line, as inspection prints them."""
        if self.running > 0:
            return (
                f"Id={name}\nLoadState=loaded\nActiveState=active\nSubState=running\n"
                f"Result=success\nExecMainCode=0\nExecMainStatus=0\n"
                f"InvocationID={self.invocation_id}\npopulated {int(not self.exiting)}\n"
            )
        failed = self.exit_status != 0 or self.result != "success"
        state = (
            "ActiveState=failed\nSubState=failed"
            if failed
            else "ActiveState=active\nSubState=exited"
        )
        return (
            f"Id={name}\nLoadState=loaded\n{state}\nResult={self.result}\n"
            f"ExecMainCode={self.exec_main_code}\nExecMainStatus={self.exit_status}\n"
            f"InvocationID={self.invocation_id}\npopulated 0\n"
        )


def finished_unit(invocation: int, *, failed: bool = False) -> NativeUnit:
    """A retained unit whose run ended, successfully or not."""
    return NativeUnit(
        0,
        1 if failed else 0,
        "exit-code" if failed else "success",
        invocation_id=f"{invocation:032x}",
    )


@dataclass
class NativeSystemd:
    """The server's systemd and privilege, as an apply run's submission and inspection see them.

    Answers the commands of ``bootstrap.native`` on a ``FakeServer``: tests choose the
    payload's exit status and systemd result, how long the unit runs, where the connection
    is lost, and what the closure probe reports. A successful cleanup clears the units it
    names. It establishes nothing about real systemd, flock or APT behaviour; the tests
    tagged ssh do.
    """

    root: bool = False
    sudo_allowed: bool = True
    # Finished units counted as retained besides ``units``, which list with no details.
    retained: int = 0
    exit_status: int = 0
    result: str = "success"
    exec_main_code: int = 1
    # How many inspections find the unit running before it is terminal.
    running: int = 0
    # Each of those inspections races the unit's exit; see ``NativeUnit.exiting``.
    exiting: bool = False
    # systemd-run refuses the unit and creates nothing.
    reject: bool = False
    # The connection ends after systemd-run started the unit, before its answer arrives.
    lose_acknowledgement: bool = False
    # The connection ends at this inspection (counted from 1), or the worker stops there.
    lose_at_inspection: int = 0
    stop_worker_at_inspection: int = 0
    boot_id: str = BOOT_ID
    # The monotonic clock the closure probe reads, in hundredths of a second.
    uptime_centiseconds: int = 0
    # The closure probe's exit status: 0 took the lock, 10 held, 11 unsafe.
    probe_exit: int = 0
    # Bootstrap units whose control groups have processes, as the probe counts them.
    probe_populated: int = 0
    dpkg_status: str = "c" * 64
    dpkg_status_after: str = ""
    # Called when systemd starts a submitted unit, to change what later reads find.
    on_submit: Callable[[], None] | None = None
    units: dict[str, NativeUnit] = field(default_factory=dict)
    submissions: list[str] = field(default_factory=list)
    probes: int = 0
    inspections: int = 0

    def answer(self, remote: FakeServer) -> None:
        if self._answer not in remote.answers:
            remote.answers.append(self._answer)

    def _answer(self, command: str) -> CommandResult | None:
        if command == native.USER_ID:
            return CommandResult(0, "0\n" if self.root else "1000\n")
        if command.startswith((f"sudo -n -l {native.SYSTEMD_RUN} ", "sudo -n -l /usr/bin/sh -c ")):
            return CommandResult(0 if self.sudo_allowed else 1, "")
        if command == native.RETAINED_UNITS:
            lines = "".join(
                f"{name} loaded active exited Barectl reviewed apply\n"
                for name in [*self._synthetic(), *self.units]
            )
            return CommandResult(0, lines)
        if command == native.RETAINED_STATES:
            reports = "".join(unit.report(name) for name, unit in self.units.items())
            return CommandResult(0, f"{self.boot_id}\n{reports}")
        if command == native.DPKG_STATUS_DIGEST:
            digest = self.dpkg_status_after if self.submissions and self.dpkg_status_after else ""
            return CommandResult(0, f"{digest or self.dpkg_status}  /var/lib/dpkg/status\n")
        if command.startswith((native.SYSTEMD_RUN, f"sudo -n {native.SYSTEMD_RUN}")):
            return self._submit(command)
        if command.startswith(("/usr/bin/sh -c ", "sudo -n /usr/bin/sh -c ")):
            return self._probe(command)
        if command.startswith("cat /proc/sys/kernel/random/boot_id; systemctl show"):
            return self._inspect(command)
        return None

    def _synthetic(self) -> list[str]:
        return [f"barectl-apply-{index:032x}.service" for index in range(self.retained)]

    def _submit(self, command: str) -> CommandResult:
        self.submissions.append(command)
        found = _SUBMITTED_UNIT.search(command)
        if found is None or self.reject:
            return CommandResult(1, "")
        self.units[found[1]] = NativeUnit(
            self.running, self.exit_status, self.result, self.exec_main_code, exiting=self.exiting
        )
        if self.exit_status == 0:
            for cleared in _CLEARED.findall(command):
                self.units.pop(cleared, None)
        if self.on_submit is not None:
            self.on_submit()
        if self.lose_acknowledgement:
            raise ConnectionFailed("The connection to web.example.com ended.")
        return CommandResult(0, "")

    def _probe(self, command: str) -> CommandResult:
        self.probes += 1
        if self.probe_exit:
            return CommandResult(self.probe_exit, "")
        name = re.findall(r"barectl-apply-[0-9a-f]{32}\.service", command)[-1]
        loaded = "loaded" if name in self.units else "not-found"
        return CommandResult(
            0,
            f"{self.boot_id}\n{self.uptime_centiseconds}\npopulated {self.probe_populated}\n"
            f"{loaded}\n",
        )

    def _inspect(self, command: str) -> CommandResult:
        self.inspections += 1
        if self.inspections == self.lose_at_inspection:
            raise ConnectionFailed("The connection to web.example.com ended.")
        if self.inspections == self.stop_worker_at_inspection:
            raise SystemExit(1)
        name = next(n for n in re.findall(r"barectl-apply-[0-9a-f]{32}\.service", command))
        unit = self.units.get(name)
        if unit is None:
            report = (
                f"Id={name}\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainCode=0\nExecMainStatus=0\nInvocationID=\n"
                "populated 0\n"
            )
        else:
            report = unit.report(name)
            if unit.running > 0:
                unit.running -= 1
        return CommandResult(0, f"{self.boot_id}\n{report}")
