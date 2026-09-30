"""docs/adr/0008-review-each-ubuntu-release-by-its-own-policy.md"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from . import native
from .models import Action, PlanEffect
from .releases import RELEASES, Release

# Increase whenever any definition below changes.
PROFILE_REVISION = 5
HTTP_PORT = 80
MARIADB_PORT = 3306
# docs/adr/0006-use-native-bootstrap-execution.md#submission
APPLY_ENTRYPOINT = "/usr/bin/systemd-run"

type LinkRule = Callable[[str, str], bool]


@dataclass(frozen=True)
class TreeSpec:
    """A configuration directory owned by one package, with the links it may contain."""

    root: str
    # The package whose installation creates the directory. Without it, the directory must
    # not exist: anything there is leftover or custom configuration.
    owner: str
    links: LinkRule
    # Other packages whose configuration files are under the directory.
    packages: tuple[str, ...] = ()
    # Files a package's maintainer scripts write under the directory, by path, with that
    # package and the file's MD5 as written. Only root may read some of them.
    generated: Mapping[str, tuple[str, str]] = field(default_factory=dict)


@dataclass(frozen=True)
class Releases:
    """The releases of a profile's software that share its package names and directories."""

    # The supported release, as the operator knows it, such as "PHP 8.3".
    name: str
    # A dpkg-query pattern naming every release's packages, such as ``php[0-9]*``.
    pattern: str
    # The supported release's package-name prefix, such as ``php8.3-``.
    supported: str
    # The directory holding each release's configuration directory, and the supported one.
    directory: str
    entry: str


@dataclass(frozen=True)
class Runtime:
    """A command-line runtime whose reported version must be its package's upstream version."""

    # Prints the version first, as ``PHP 8.3.6 (cli) ...``.
    command: str
    package: str
    # What the first line must be, with ``{version}`` for the package's upstream version.
    first_line: str


@dataclass(frozen=True)
class DataSpec:
    """A database engine's data directory, which the root package's maintainer scripts
    create and initialize; no package owns it."""

    directory: str
    # The account the directory and its marker belong to.
    owner: str
    # What exists once the engine is initialized, and its type as stat names it, such as
    # a "directory" of system tables or a "regular file" naming the data's version.
    marker: str
    marker_type: str
    # What the root package's installation effects say about initialization.
    effect: str
    # Paths the engine's packages create, such as its log directory, which must not exist
    # while the root package is not installed.
    remnants: tuple[str, ...] = ()
    # A directory whose entries must be among the named ones, such as the versions under
    # an engine's data root.
    listing: tuple[str, frozenset[str]] | None = None

    @property
    def paths(self) -> tuple[str, ...]:
        return (self.directory, self.marker, *self.remnants)


@dataclass(frozen=True)
class Alternative:
    """An update-alternatives link the profile's configuration is read through."""

    name: str
    link: str
    # What the link resolves to once the profile is installed.
    value: str

    @property
    def state(self) -> str:
        """dpkg's record of the alternative, which revalidation digests."""
        return f"/var/lib/dpkg/alternatives/{self.name}"


@dataclass(frozen=True)
class Profile:
    action: Action
    intent: str
    # The packages the operator asks for, installed at exact reviewed versions.
    roots: tuple[str, ...]
    # Every package whose state is evidence even before a simulation names it.
    packages: tuple[str, ...]
    units: tuple[str, ...]
    trees: tuple[TreeSpec, ...]
    # Files ucf installs under the trees count as defaults when unmodified.
    ucf: bool
    # The TCP port the distribution's default configuration listens on, if any.
    port: int | None
    # The command an apply run runs as root after its changes: the service's own syntax
    # check, or a readiness check whose exact output is qualified.
    check: native.Check
    # The effect naming what the profile exposes, and the postconditions besides the
    # packages and marks every package profile verifies.
    exposure: tuple[PlanEffect.Kind, str]
    postconditions: tuple[str, ...]
    # What listens on the port and socket, as the review names it.
    serves: str
    # The local socket the distribution's default configuration listens on, if any.
    socket: str | None = None
    releases: Releases | None = None
    runtime: Runtime | None = None
    # The process listening on the port, and the addresses it listens on; ``exclusive``
    # when it must listen on those addresses only.
    process: str = ""
    addresses: frozenset[str] = frozenset()
    exclusive: bool = False
    # The release archive components an installation's closure may come from, each of
    # whose authenticated indexes an installation needs.
    components: tuple[str, ...] = ("main",)
    # How the installation effect names the archives, when not the release's alone.
    archives: str = ""
    # dpkg-query patterns of packages that conflict with the profile, installed or left.
    conflicts: tuple[str, ...] = ()
    data: DataSpec | None = None
    # Paths that must not exist, such as another engine's data or configuration.
    forbidden: tuple[str, ...] = ()
    alternative: Alternative | None = None
    # Preparation runs ``check`` with privilege while the service runs, so an established
    # installation is recognized only when the check holds.
    readiness: bool = False
    # An unprivileged read of the effective configuration, with its qualified output.
    defaults: native.Check | None = None
    # The unit whose running state is the service's; the first unit unless named, such as
    # a cluster's unit under an umbrella unit that only stays active (exited).
    serving: str = ""
    # Why an established installation whose readiness check shows another output is refused.
    readiness_failure: str = ""
    # What a failed final check or failed verification means, when not the stock wording.
    check_failure: str = ""
    verification_failure: str = ""

    @property
    def serving_unit(self) -> str:
        return self.serving or self.units[0]

    @property
    def serves_capitalized(self) -> str:
        return self.serves[:1].upper() + self.serves[1:]

    @property
    def layout(self) -> dict[str, frozenset[str]]:
        """Directories whose entries must be among the named ones: the releases' directory
        holds only the supported release, and that release's directory only the trees."""
        if self.releases is None:
            return {}
        own = f"{self.releases.directory}/{self.releases.entry}"
        return {
            self.releases.directory: frozenset({self.releases.entry}),
            own: frozenset(
                spec.root.removeprefix(f"{own}/")
                for spec in self.trees
                if spec.root.startswith(f"{own}/")
            ),
        }

    @property
    def listings(self) -> dict[str, frozenset[str]]:
        """Every directory whose entries preparation lists, with the allowed names."""
        listed = dict(self.layout)
        if self.data is not None and self.data.listing is not None:
            directory, names = self.data.listing
            listed[directory] = names
        return listed

    @property
    def paths(self) -> tuple[str, ...]:
        """The paths whose type and owner preparation reads and revalidation digests."""
        return (*(self.data.paths if self.data else ()), *self.forbidden)

    @property
    def revalidation(self) -> str:
        """The package digest a plan records and its apply payload recomputes."""
        alternative = self.alternative
        return native.package_digest(
            self.units,
            tuple(spec.root for spec in self.trees),
            self.port,
            ucf=self.ucf,
            listings=tuple(self.listings),
            socket=self.socket,
            paths=self.paths,
            private=tuple(path for spec in self.trees for path in spec.generated),
            hashed=(alternative.state,) if alternative else (),
            resolved=(alternative.link,) if alternative else (),
        )


def _nginx_links(path: str, target: str) -> bool:
    if path == "/etc/nginx/sites-enabled/default":
        return target == "/etc/nginx/sites-available/default"
    module = re.fullmatch(r"/etc/nginx/modules-enabled/[0-9]{2}-mod-([a-z0-9-]+)\.conf", path)
    return module is not None and target == (
        f"/usr/share/nginx/modules-available/mod-{module[1]}.conf"
    )


def _php_links(php: str) -> LinkRule:
    """Links from the SAPIs' conf.d to the release's mods-available, as phpenmod makes them."""
    version = re.escape(php)

    def links(path: str, target: str) -> bool:
        module = re.fullmatch(
            rf"/etc/php/{version}/(?:fpm|cli)/conf\.d/[0-9]{{2}}-([a-z0-9_]+)\.ini", path
        )
        return module is not None and target == f"/etc/php/{php}/mods-available/{module[1]}.ini"

    return links


def _no_links(_path: str, _target: str) -> bool:
    return False


def _mysql_links(path: str, target: str) -> bool:
    """The my.cnf alternative, which update-alternatives manages."""
    return path == "/etc/mysql/my.cnf" and target == "/etc/alternatives/my.cnf"


def nginx(release: Release) -> Profile:
    unit = "nginx.service"
    return Profile(
        Action.NGINX,
        f"Install the distribution-default Nginx web server from {release.name} packages.",
        roots=("nginx",),
        packages=("nginx", "nginx-common", "needrestart"),
        units=(unit,),
        trees=(TreeSpec("/etc/nginx", "nginx-common", _nginx_links),),
        ucf=False,
        port=HTTP_PORT,
        check=native.Check(("/usr/sbin/nginx", "-t", "-q")),
        exposure=(
            PlanEffect.Kind.HTTP_LISTENER,
            (
                f"The distribution's default site serves HTTP on port {HTTP_PORT} on every "
                "IPv4 and IPv6 address. Check the server's firewall policy before applying; "
                "Barectl does not change it."
            ),
        ),
        postconditions=(
            "nginx -t accepts the configuration.",
            f"{unit} is enabled and active.",
            f"Port {HTTP_PORT} accepts connections on IPv4 and IPv6.",
            "Discovery observes Nginx with the default site file.",
        ),
        serves="the distribution's default site",
        process="nginx",
        # As ss reports a socket listening on every IPv4 and every IPv6 address.
        addresses=frozenset({"0.0.0.0", "[::]"}),  # noqa: S104 - reported addresses, not a bind
    )


def php(release: Release) -> Profile:
    version = release.php
    prefix = f"php{version}-"
    links = _php_links(version)
    unit = f"php{version}-fpm.service"
    socket = f"/run/php/php{version}-fpm.sock"
    return Profile(
        Action.PHP,
        f"Install the distribution-default PHP {version} FPM and CLI from {release.name} packages.",
        roots=(f"{prefix}fpm", f"{prefix}cli"),
        packages=(
            f"{prefix}fpm",
            f"{prefix}cli",
            f"{prefix}common",
            *release.php_extras,
            "php-common",
            "needrestart",
        ),
        units=(unit,),
        trees=(
            TreeSpec(f"/etc/php/{version}/fpm", f"{prefix}fpm", links),
            TreeSpec(f"/etc/php/{version}/cli", f"{prefix}cli", links),
            TreeSpec(f"/etc/php/{version}/mods-available", f"{prefix}common", _no_links),
        ),
        ucf=True,
        port=None,
        check=native.Check((f"/usr/sbin/php-fpm{version}", "-t")),
        exposure=(
            PlanEffect.Kind.LOCAL_SOCKET,
            (
                f"The distribution's default www pool listens on the local socket {socket} "
                "and opens no network port; when the service starts, its unit registers "
                "/run/php/php-fpm.sock as an alternative for that socket. No web server is "
                "installed, and no site, route, pool, extension, database, certificate or "
                "application user is created."
            ),
        ),
        postconditions=(
            f"php-fpm{version} -t accepts the configuration.",
            f"php{version} -v reports the installed php{version}-cli version.",
            f"{unit} is enabled and active.",
            f"The default www pool listens on {socket}.",
            f"Discovery observes PHP-FPM {version} with the www pool.",
        ),
        serves="the distribution's default pool",
        socket=socket,
        releases=Releases(f"PHP {version}", "php[0-9]*", prefix, "/etc/php", version),
        runtime=Runtime(f"php{version} -v", f"{prefix}cli", "PHP {version} (cli) "),
        # One package of the closure, on both releases, comes from universe.
        components=("main", "universe"),
    )


MARIADB_SOCKET = "/run/mysqld/mysqld.sock"
# docs/v0.3-qualification.md#mariadb-profile: the account, authentication and absence of
# anonymous and remote root accounts that the distribution's initialization leaves.
_MARIADB_ADMINISTRATION = (
    "SELECT CURRENT_USER(); SHOW CREATE USER 'root'@'localhost'; "
    "SELECT COUNT(User) FROM mysql.global_priv WHERE User = '' "
    "OR (User = 'root' AND Host <> 'localhost')"
)
_MARIADB_ADMINISTRATOR = (
    "root@localhost\n"
    "CREATE USER `root`@`localhost` IDENTIFIED VIA mysql_native_password USING 'invalid' "
    "OR unix_socket\n"
    "0"
)
# Every release's MariaDB data directory, MySQL's own, and option files outside
# /etc/mysql that the server would also read.
_FORBIDDEN = ("/var/lib/mysql", "/var/lib/mariadb", "/var/lib/mysql-files", "/etc/my.cnf")


def mariadb(release: Release) -> Profile:
    packaged = release.mariadb
    data = packaged.data
    unit = "mariadb.service"
    addresses = frozenset({"127.0.0.1"})
    return Profile(
        Action.MARIADB,
        f"Install the distribution MariaDB {packaged.series} server from {release.name} packages.",
        roots=("mariadb-server",),
        packages=(
            "mariadb-server",
            "mariadb-server-core",
            "mariadb-client",
            "mariadb-client-core",
            "mariadb-common",
            "mysql-common",
            "galera-4",
            "needrestart",
        ),
        units=(unit,),
        trees=(
            TreeSpec(
                "/etc/mysql",
                "mysql-common",
                _mysql_links,
                packages=("mariadb-common", "mariadb-client", "mariadb-server"),
                generated={"/etc/mysql/debian.cnf": ("mariadb-server", packaged.debian_cnf)},
            ),
        ),
        ucf=False,
        port=MARIADB_PORT,
        check=native.Check(
            (
                "/usr/bin/mariadb",
                "--no-defaults",
                "--protocol=socket",
                f"--socket={MARIADB_SOCKET}",
                "--user=root",
                "-N",
                "-B",
                "-e",
                _MARIADB_ADMINISTRATION,
            ),
            _MARIADB_ADMINISTRATOR,
        ),
        exposure=(
            PlanEffect.Kind.DATABASE_LISTENERS,
            (
                f"MariaDB listens on the local socket {MARIADB_SOCKET} and on port "
                f"{MARIADB_PORT} at 127.0.0.1 only, as the distribution's configuration binds "
                "it; it opens no public listener. No database, database user, password or PHP "
                "driver is created or installed."
            ),
        ),
        postconditions=(
            (
                "As root, without a password or option files, mariadb connects through "
                f"{MARIADB_SOCKET} as root@localhost, which authenticates by unix_socket with "
                "no usable password, and no anonymous or remote root account exists."
            ),
            f"{unit} is enabled and running, from the distribution's unit.",
            f"{data} is owned by mysql and holds the initialized system tables.",
            (f"MariaDB listens on {MARIADB_SOCKET} and on port {MARIADB_PORT} at 127.0.0.1 only."),
            (
                "/etc/mysql/my.cnf resolves to /etc/mysql/mariadb.cnf, /etc/my.cnf does not "
                "exist, and mariadbd --print-defaults reports the distribution's options."
            ),
            "mariadbd --version reports the installed mariadb-server version.",
            "Discovery observes MariaDB with its packages and service.",
        ),
        serves="the distribution's MariaDB server",
        socket=MARIADB_SOCKET,
        runtime=Runtime(
            "/usr/sbin/mariadbd --version",
            "mariadb-server",
            "/usr/sbin/mariadbd  Ver {version}-MariaDB",
        ),
        process="mariadbd",
        addresses=addresses,
        exclusive=True,
        components=packaged.components,
        archives=(
            ""
            if packaged.components == ("main",)
            else f"{release.name} archives' {' and '.join(packaged.components)} components"
        ),
        conflicts=(
            "mysql-server*",
            "mysql-client*",
            "mysql-community-*",
            "mysql-router*",
            "default-mysql-server*",
            "default-mysql-client*",
            "percona-*",
            "mariadb-server-[0-9]*",
            "mariadb-server-core-[0-9]*",
            "mariadb-client-[0-9]*",
            "mariadb-client-core-[0-9]*",
        ),
        data=DataSpec(
            data,
            "mysql",
            f"{data}/mysql",
            "directory",
            (
                "The server package's maintainer scripts create and initialize the data "
                f"directory {data}, owned by mysql, with the system tables and the "
                "administrative account root@localhost, which has no password and "
                "authenticates only the local root user through the Unix socket. An "
                "interrupted installation can leave a partly initialized directory; Barectl "
                "never removes, migrates or adopts database data."
            ),
            remnants=("/var/log/mysql",),
        ),
        forbidden=tuple(path for path in _FORBIDDEN if path != data),
        alternative=Alternative("my.cnf", "/etc/mysql/my.cnf", "/etc/mysql/mariadb.cnf"),
        readiness=True,
        readiness_failure=(
            "The distribution's MariaDB server is installed, but its administration is not "
            "the distribution's: as root, without a password or option files, the local "
            "socket does not connect as root@localhost authenticated only by unix_socket, or "
            "anonymous or remote root accounts exist. Bootstrap does not adopt custom "
            "authentication; restore it through ordinary administration, then prepare again."
        ),
        defaults=native.Check(
            ("/usr/sbin/mariadbd", "--print-defaults"),
            "/usr/sbin/mariadbd would have been started with the following arguments:\n"
            + packaged.defaults,
        ),
        check_failure=(
            "The changes were made, but MariaDB did not show the distribution's local "
            "administration afterwards: root could not connect through the socket without a "
            "password, or connected as another account, with another authentication, or "
            "beside anonymous or remote root accounts. Barectl does not roll back: inspect "
            "the unit's journal and the accounts with sudo mariadb, repair them through "
            "ordinary administration, then prepare a new plan."
        ),
        verification_failure=(
            "The run completed, but the MariaDB profile's postconditions do not hold: a "
            "package is not installed at its reviewed version, dpkg reports a problem, an "
            "earlier package's automatic mark changed, mariadb.service is not enabled and "
            "running, the data directory is not initialized, MariaDB listens elsewhere than "
            "its local socket and 127.0.0.1, its effective configuration is not the "
            "distribution's, or mariadbd reports another version. Barectl does not repair or "
            "roll back; inspect the server through ordinary administration. The refreshed "
            "discovery shows what is there now."
        ),
    )


PROFILES = {
    version: {
        profile.action: profile for profile in (nginx(release), php(release), mariadb(release))
    }
    for version, release in RELEASES.items()
}
PACKAGE_ACTIONS = frozenset({Action.NGINX, Action.PHP, Action.MARIADB})


def profile(release: Release, action: Action) -> Profile:
    return PROFILES[release.version][action]


METADATA_REFRESH_INTENT = "Refresh the authenticated package indexes from the configured sources."
CLEAR_RESULTS_INTENT = "Clear finished bootstrap runs that the server's systemd retains."

# What each admitted hook does to native caches, for the metadata refresh review.
HOOK_EFFECTS = {
    "apt": "records the update-success stamp in /var/lib/apt/periodic",
    "command-not-found": "rebuilds the command-not-found database",
    "update-notifier-common": "refreshes the login message's available-updates count",
    "ubuntu-pro-client": "starts Ubuntu Pro's apt-news and esm-cache services when run as root",
    "debconf": "preconfigures packages with debconf before dpkg unpacks them",
    "needrestart": "checks for services that use outdated libraries after dpkg runs",
    "packagekit": "tells PackageKit, when its service is installed, that package state changed",
    "appstream": "refreshes the AppStream catalog in /var/cache/swcatalog",
    "snapd": "suggests snaps after the apt command installs packages",
}
# A configuration key is a hook when any part of it names one.
HOOK_KEY = re.compile(r"(?i)(invoke|hook|install-pkgs|tools::options)")
# APT options that weaken authentication or override package selection or dpkg, which a
# reviewed transaction must not depend on, as keys APT compares in lower case.
AUTHENTICATION_OPTIONS = frozenset(
    {
        "apt::get::allowunauthenticated",
        "acquire::allowinsecurerepositories",
        "acquire::allowdowngradetoinsecurerepositories",
        "acquire::allowweakrepositories",
        "apt::get::force-yes",
        "apt::get::allow-downgrades",
        "apt::get::allow-remove-essential",
        "apt::get::allow-change-held-packages",
    }
)
# Options that must not be turned off, such as checking a Release file's expiry.
REQUIRED_OPTIONS = frozenset({"acquire::check-valid-until"})
# Options whose value must stay the distribution's; absence also keeps the default.
FIXED_OPTIONS = {
    "dir::bin::dpkg": "/usr/bin/dpkg",
    "apt::default-release": "",
    "dpkg::chroot-directory": "/",
}
# Options that must have no list entries, such as extra dpkg command-line options.
EMPTY_LISTS = frozenset({"dpkg::options"})
