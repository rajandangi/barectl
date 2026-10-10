"""docs/adr/0008-review-each-ubuntu-release-by-its-own-policy.md"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final

from . import native, php_supply
from .models import Action, PlanEffect
from .releases import RELEASES, Release

# Increase whenever any definition below changes.
PROFILE_REVISION = 12
HTTP_PORT = 80
MARIADB_PORT = 3306
# docs/adr/0006-use-native-bootstrap-execution.md#submission
APPLY_ENTRYPOINT = "/usr/bin/systemd-run"

type LinkRule = Callable[[str, str], bool]
# docs/databases.md#site-aware-readiness: the tree rule the databases app supplies.
SITE_CONVENTION = "site-convention"


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
    # package and the file's MD5 as written, or ``None`` when what they write depends on the
    # server, such as its locale. Only root may read some of them.
    generated: Mapping[str, tuple[str, str | None]] = field(default_factory=dict)
    # The name of a rule another app supplies to judge the directory instead, such as
    # "site-convention", which admits Barectl's site pools; empty for the distribution's.
    rule: str = ""


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
    # What an unexpected entry in the supported release's directory usually is.
    example: str = "another server API's configuration"


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
    # Directories whose entries must be among the named ones, such as the versions under
    # an engine's data root; entries starting with "." are not data.
    listings: tuple[tuple[str, frozenset[str]], ...] = ()

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.directory, self.marker, *self.remnants)))


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
    exposure: tuple[PlanEffect.Kind, str] | None
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
    # An unprivileged read of the effective configuration, with its qualified output, and
    # the settings it names that depend on the server, such as its locale, left out.
    defaults: native.Check | None = None
    defaults_ignored: frozenset[str] = frozenset()
    # The unit whose running state is the service's; the first unit unless named, such as
    # a cluster's unit under an umbrella unit that only stays active (exited).
    serving: str = ""
    # Why an established installation whose readiness check shows another output is refused.
    readiness_failure: str = ""
    # Whether a review may propose starting or enabling a stopped installation; when not,
    # what ordinary administration does instead.
    startable: bool = True
    stopped: str = ""
    # What a failed final check or failed verification means, when not the stock wording.
    check_failure: str = ""
    verification_failure: str = ""
    # Packages that must already be installed, and what ordinary administration or which
    # plan installs them; a review never installs them as dependencies.
    prerequisites: tuple[str, ...] = ()
    prerequisite: str = ""
    # When set, (roots, package): an installation requests each of the roots at the
    # installed version of the package, which they depend on exactly.
    pinned: tuple[tuple[str, ...], str] | None = None
    # The PHP modules the root enables, as (conf.d link name, module), such as
    # ("20-mysqli", "mysqli"), which every SAPI's conf.d links and php-fpm -m lists.
    modules: tuple[tuple[str, str], ...] = ()
    # Lists the modules the service loads, as php-fpm -m does, reading only its
    # configuration and writing nothing.
    module_list: str = ""
    # Lists the modules the selected CLI loads, as ``php -m`` does.
    cli_module_list: str = ""
    # The root package that enables each of ``modules``, in order; the first root when empty.
    module_roots: tuple[str, ...] = ()
    # Modules the installed PHP build must already load in the CLI and in PHP-FPM, which no
    # root enables: they come from the build or from php-common.
    builtins: tuple[str, ...] = ()
    # The service the run reloads after its check, so running workers load the change.
    reload: str = ""
    # What the maintainer scripts do to the service while dpkg runs, when not the stock
    # enabling and starting.
    maintainer: str = ""
    # The installed package that provides the units, when not the first root.
    service: str = ""
    # Whether bootstrap proposes enabling and starting the units. Certbot's belong to
    # renewal setup, which enables its timer only after the guard (docs/tls.md).
    managed_units: bool = True
    # Drop-ins another action installs and verifies, which the units may have.
    drop_ins: frozenset[str] = frozenset()
    # What happens to the units while the maintainer scripts run, when an action inhibits
    # them rather than letting the scripts enable and start them.
    maintainer_start: str = ""
    php_version: str = ""
    php_supply: str = "ubuntu"

    @property
    def service_package(self) -> str:
        """The package whose installation provides the units: the first root unless the
        profile builds on another package's service."""
        return self.service or self.roots[0]

    @property
    def serving_unit(self) -> str:
        return self.serving or (self.units[0] if self.units else "")

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
            self.releases.directory: (
                frozenset(php_supply.ELIGIBLE_BRANCHES)
                if self.php_supply == "sury"
                else frozenset({self.releases.entry})
            ),
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
        if self.data is not None:
            listed.update(self.data.listings)
        return listed

    def effective(self, output: str) -> str:
        """The defaults read's output as compared: stripped lines, without ignored settings."""
        lines = (line.rstrip() for line in output.strip().splitlines())
        return "\n".join(
            line for line in lines if line.partition(" = ")[0] not in self.defaults_ignored
        )

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
            listings=tuple(self.layout),
            data_listings=tuple(dict(self.data.listings)) if self.data else (),
            socket=self.socket,
            paths=self.paths,
            private=tuple(path for spec in self.trees for path in spec.generated),
            hashed=(alternative.state,) if alternative else (),
            resolved=(alternative.link,) if alternative else (),
        )


def unit_file(name: str) -> str:
    """The distribution's unit file of ``name``: its template's for an instance."""
    template, at, _ = name.partition("@")
    return (
        f"/usr/lib/systemd/system/{template}@.service" if at else f"/usr/lib/systemd/system/{name}"
    )


def enablements(name: str) -> frozenset[str]:
    """The enablement states supported for ``name``: a template's instance, such as a
    PostgreSQL cluster's unit, is enabled at runtime by its package's generator."""
    return frozenset({"enabled-runtime"}) if "@" in name else frozenset({"enabled", "disabled"})


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


def php(release: Release, *, version: str | None = None, supply: str = "ubuntu") -> Profile:
    version = php_supply.select(release, version, supply)
    prefix = f"php{version}-"
    extras = (
        release.php_extras
        if supply == "ubuntu"
        else (*((f"{prefix}opcache",) if version != "8.5" else ()), f"{prefix}readline")
    )
    links = _php_links(version)
    unit = f"php{version}-fpm.service"
    socket = f"/run/php/php{version}-fpm.sock"
    return Profile(
        Action.PHP,
        (
            f"Install the distribution-default PHP {version} FPM and CLI "
            f"from {release.name} packages."
            if supply == "ubuntu"
            else f"Install PHP {version} FPM and CLI from the approved unified PHP source."
        ),
        roots=(f"{prefix}fpm", f"{prefix}cli"),
        packages=(
            f"{prefix}fpm",
            f"{prefix}cli",
            f"{prefix}common",
            *extras,
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
        php_version=version,
        php_supply=supply,
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


POSTGRESQL_PORT = 5432
POSTGRESQL_SOCKET = "/var/run/postgresql/.s.PGSQL.5432"
# docs/bootstrap.md#postgresql: what the cluster's administrator, postgres, connecting
# through the local socket, sees of the cluster's identity, listeners and authentication.
# The cluster's identity, listeners and authentication, and that the running server uses
# exactly the configuration under /etc/postgresql: no ALTER SYSTEM or other included file,
# nothing waiting for a restart, and no file changed since the server last loaded it.
_POSTGRESQL_IDENTITY = (
    "SELECT current_user, current_setting('server_version_num')::int / 10000, "
    "(SELECT string_agg(setting, '|' ORDER BY name) FROM pg_settings WHERE name IN "
    "('data_directory', 'hba_file', 'listen_addresses', 'password_encryption', 'port', "
    "'unix_socket_directories')), "
    "(SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = 'postgres'), "
    "(SELECT count(name) FROM pg_file_settings WHERE sourcefile NOT LIKE '/etc/postgresql/%' "
    "OR NOT applied OR error IS NOT NULL), "
    "(SELECT bool_or(pending_restart) FROM pg_settings), "
    "pg_conf_load_time() >= (SELECT max((pg_stat_file(setting)).modification) FROM pg_settings "
    "WHERE name IN ('config_file', 'hba_file', 'ident_file'))"
)
# A rule's options may hold an LDAP or RADIUS secret and its error may quote the line, so
# only whether a rule has either is read.
_POSTGRESQL_RULES = (
    "SELECT concat_ws('|', type, database, user_name, address, netmask, auth_method, "
    "nullif(options IS NOT NULL, false), nullif(error IS NOT NULL, false)) "
    "FROM pg_hba_file_rules ORDER BY line_number"
)
# The rules pg_createcluster's pg_hba.conf template holds on both releases' majors.
_POSTGRESQL_HBA = (
    "local|{all}|{postgres}|peer",
    "local|{all}|{all}|peer",
    "host|{all}|{all}|127.0.0.1|255.255.255.255|scram-sha-256",
    "host|{all}|{all}|::1|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|scram-sha-256",
    "local|{replication}|{all}|peer",
    "host|{replication}|{all}|127.0.0.1|255.255.255.255|scram-sha-256",
    "host|{replication}|{all}|::1|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|scram-sha-256",
)
# Settings pg_createcluster writes from the server's locale and time zone.
_POSTGRESQL_LOCAL_SETTINGS = frozenset(
    {
        "datestyle",
        "default_text_search_config",
        "lc_messages",
        "lc_monetary",
        "lc_numeric",
        "lc_time",
        "log_timezone",
        "timezone",
    }
)


def _postgresql_settings(major: str) -> str:
    """``pg_conftool <major> main show all`` for the cluster pg_createcluster creates."""
    settings = [
        *(["autovacuum_worker_slots = 16"] if int(major) >= 18 else []),
        f"cluster_name = '{major}/main'",
        f"data_directory = '/var/lib/postgresql/{major}/main'",
        "dynamic_shared_memory_type = posix",
        f"external_pid_file = '/var/run/postgresql/{major}-main.pid'",
        f"hba_file = '/etc/postgresql/{major}/main/pg_hba.conf'",
        f"ident_file = '/etc/postgresql/{major}/main/pg_ident.conf'",
        "log_line_prefix = '%m [%p] %q%u@%d '",
        "max_connections = 100",
        "max_wal_size = 1GB",
        "min_wal_size = 80MB",
        f"port = {POSTGRESQL_PORT}",
        "shared_buffers = 128MB",
        "ssl = on",
        "ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'",
        "ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'",
        "unix_socket_directories = '/var/run/postgresql'",
    ]
    return "\n".join(settings)


def postgresql(release: Release) -> Profile:
    packaged = release.postgresql
    major = packaged.major
    server = f"postgresql-{major}"
    cluster = f"/etc/postgresql/{major}/main"
    data = f"/var/lib/postgresql/{major}/main"
    unit = f"postgresql@{major}-main.service"
    return Profile(
        Action.POSTGRESQL,
        f"Install the distribution-default PostgreSQL {major} server and its main cluster from "
        f"{release.name} packages.",
        roots=(server,),
        packages=(
            server,
            f"postgresql-client-{major}",
            "postgresql-common",
            "postgresql-client-common",
            "postgresql",
            "libpq5",
            "needrestart",
        ),
        units=("postgresql.service", unit),
        trees=(
            TreeSpec(
                cluster,
                server,
                _no_links,
                generated={
                    f"{cluster}/{name}": (server, md5)
                    for name, md5 in (
                        ("start.conf", "9bb73ac29fd5f433229675e12d493acf"),
                        ("pg_ctl.conf", "242d50c2d81898522f80f9898d455e50"),
                        ("environment", "a567730a646c4afdfc5cea58aa4bd49a"),
                        ("pg_hba.conf", packaged.hba),
                        ("pg_ident.conf", packaged.ident),
                        # Written from the server's locale and time zone; the effective
                        # settings are compared instead.
                        ("postgresql.conf", None),
                    )
                },
            ),
            TreeSpec(
                "/etc/postgresql-common",
                "postgresql-common",
                _no_links,
                packages=("postgresql-client-common",),
                generated={
                    "/etc/postgresql-common/root.crt": (
                        "postgresql-common",
                        "1d138790e9365a4fbbcf68fc66971e1e",
                    )
                },
            ),
        ),
        ucf=True,
        port=POSTGRESQL_PORT,
        check=native.Check(
            (
                "/usr/sbin/runuser",
                "-u",
                "postgres",
                "--",
                "/usr/bin/psql",
                "-X",
                "-A",
                "-t",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                "/var/run/postgresql",
                "-p",
                str(POSTGRESQL_PORT),
                "-d",
                "postgres",
                "-c",
                _POSTGRESQL_IDENTITY,
                "-c",
                _POSTGRESQL_RULES,
            ),
            "\n".join(
                (
                    (
                        f"postgres|{major}|{data}|{cluster}/pg_hba.conf|localhost|"
                        f"scram-sha-256|{POSTGRESQL_PORT}|/var/run/postgresql|t|0|f|t"
                    ),
                    *_POSTGRESQL_HBA,
                )
            ),
            limit=len(_POSTGRESQL_IDENTITY),
        ),
        exposure=(
            PlanEffect.Kind.DATABASE_LISTENERS,
            (
                f"The main cluster listens on the local socket {POSTGRESQL_SOCKET} and on port "
                f"{POSTGRESQL_PORT} at 127.0.0.1 and ::1 only, as the distribution's "
                "configuration binds it; it opens no public listener. Local connections "
                "authenticate by peer, as the connecting Linux user; TCP connections need a "
                "password, which no role has. No database, role, password or PHP driver is "
                "created or installed."
            ),
        ),
        postconditions=(
            (
                f"As postgres, psql connects through {POSTGRESQL_SOCKET} to the PostgreSQL "
                f"{major} main cluster, whose data directory, listeners, socket and password "
                "encryption are the distribution's, whose postgres role has no password, and "
                "whose authentication rules are exactly the distribution's pg_hba.conf."
            ),
            (
                f"{unit} is running and postgresql.service is active, both enabled, from the "
                "distribution's units."
            ),
            f"{data} is owned by postgres, and no other major or cluster exists.",
            (
                f"The cluster listens on {POSTGRESQL_SOCKET} and on port {POSTGRESQL_PORT} at "
                "127.0.0.1 and ::1 only."
            ),
            (
                f"pg_conftool {major} main show all reports the distribution's settings, apart "
                "from those written from the server's locale and time zone."
            ),
            f"postgres --version reports the installed {server} version.",
            "Discovery observes PostgreSQL with its main cluster's unit.",
        ),
        serves="the distribution's PostgreSQL main cluster",
        socket=POSTGRESQL_SOCKET,
        releases=Releases(
            f"PostgreSQL {major}",
            "postgresql-[0-9]*",
            f"{server}",
            "/etc/postgresql",
            major,
            example="another cluster's configuration",
        ),
        runtime=Runtime(
            f"/usr/lib/postgresql/{major}/bin/postgres --version",
            server,
            "postgres (PostgreSQL) {version} ",
        ),
        process="postgres",
        addresses=frozenset({"127.0.0.1", "[::1]"}),
        exclusive=True,
        data=DataSpec(
            data,
            "postgres",
            # Only postgres may search the data directory; the readiness check proves it.
            data,
            "directory",
            (
                f"The {server} package's maintainer scripts create the main cluster with "
                f"pg_createcluster: the data directory {data}, owned by postgres, and "
                f"its configuration under {cluster}, whose locale, encoding and time zone "
                "settings follow the server's own. The postgres role has no password and "
                "authenticates only the local postgres user by peer. An interrupted "
                "installation can leave a partly created cluster; Barectl never removes, "
                "migrates or adopts database data."
            ),
            remnants=("/var/lib/postgresql", "/var/log/postgresql"),
            listings=(
                ("/var/lib/postgresql", frozenset({major})),
                (f"/var/lib/postgresql/{major}", frozenset({"main"})),
            ),
        ),
        readiness=True,
        readiness_failure=(
            f"The distribution's PostgreSQL {major} main cluster is installed, but its "
            "administration is not the distribution's: as postgres, through the local socket, "
            "the cluster does not report the distribution's data directory, listeners, "
            "password encryption and password-less postgres role, its authentication rules "
            "are not exactly the distribution's pg_hba.conf, or the running server does not "
            "use exactly the configuration under /etc/postgresql, such as after ALTER SYSTEM, "
            "a change waiting for a restart, or an edited file not yet reloaded. Bootstrap "
            "does not adopt custom configuration or authentication; restore it through "
            "ordinary administration, reload or restart the cluster, then prepare again."
        ),
        startable=False,
        stopped=(
            "Bootstrap establishes only a running cluster, whose administration it can check, "
            "and never starts one it did not create, which may be partly initialized. Start "
            f"the cluster through ordinary administration, such as sudo pg_ctlcluster {major} "
            "main start, then prepare again."
        ),
        defaults=native.Check(
            ("/usr/bin/pg_conftool", major, "main", "show", "all"), _postgresql_settings(major)
        ),
        defaults_ignored=_POSTGRESQL_LOCAL_SETTINGS,
        serving=unit,
        check_failure=(
            "The changes were made, but the PostgreSQL main cluster did not show the "
            "distribution's local administration afterwards: postgres could not connect "
            "through the socket, or the cluster's data directory, listeners, password "
            "encryption, the postgres role's password or its authentication rules differ. "
            "Barectl does not roll back: inspect the units' journals and the cluster with "
            "sudo -u postgres psql, repair it through ordinary administration, then prepare a "
            "new plan."
        ),
        verification_failure=(
            "The run completed, but the PostgreSQL profile's postconditions do not hold: a "
            "package is not installed at its reviewed version, dpkg reports a problem, an "
            "earlier package's automatic mark changed, the main cluster's unit is not running "
            "or postgresql.service is not active, the data directory is missing, the cluster "
            "listens elsewhere than its local socket, 127.0.0.1 and ::1, its settings are not "
            "the distribution's, or postgres reports another version. Barectl does not repair "
            "or roll back; inspect the server through ordinary administration. The refreshed "
            "discovery shows what is there now."
        ),
    )


# docs/v0.3-qualification.md#php-database-drivers: the modules each driver package enables,
# with the conf.d link names phpenmod gives them on both releases.
_DRIVER_MODULES = {
    Action.PHP_MYSQL: (
        ("mysql", "MariaDB"),
        (("10-mysqlnd", "mysqlnd"), ("20-mysqli", "mysqli"), ("20-pdo_mysql", "pdo_mysql")),
    ),
    Action.PHP_PGSQL: (
        ("pgsql", "PostgreSQL"),
        (("20-pgsql", "pgsql"), ("20-pdo_pgsql", "pdo_pgsql")),
    ),
}
DRIVER_ACTIONS = frozenset(_DRIVER_MODULES)
# The actions that review one selected PHP branch's packages besides the PHP profile.
BRANCH_ACTIONS = frozenset({*DRIVER_ACTIONS, Action.PHP_WORDPRESS})


def php_driver(
    release: Release, action: Action, *, version: str | None = None, supply: str = "ubuntu"
) -> Profile:
    """docs/databases.md#php-database-drivers"""
    (suffix, engine), modules = _DRIVER_MODULES[action]
    version = php_supply.select(release, version, supply)
    prefix = f"php{version}-"
    root = f"{prefix}{suffix}"
    links = _php_links(version)
    unit = f"php{version}-fpm.service"
    socket = f"/run/php/php{version}-fpm.sock"
    names = ", ".join(module for _, module in modules)
    return Profile(
        action,
        (
            f"Install the distribution PHP {version} {engine} driver ({root}) "
            f"from {release.name} packages."
            if supply == "ubuntu"
            else f"Install PHP {version} {engine} driver ({root}) "
            "from the approved unified PHP source."
        ),
        roots=(root,),
        packages=(
            root,
            f"{prefix}common",
            f"{prefix}fpm",
            f"{prefix}cli",
            "php-common",
            "needrestart",
            *(("libpq5",) if action == Action.PHP_PGSQL else ()),
        ),
        units=(unit,),
        trees=(
            TreeSpec(f"/etc/php/{version}/fpm", f"{prefix}fpm", links, rule=SITE_CONVENTION),
            TreeSpec(f"/etc/php/{version}/cli", f"{prefix}cli", links),
            TreeSpec(f"/etc/php/{version}/mods-available", f"{prefix}common", _no_links),
        ),
        ucf=True,
        port=None,
        check=native.Check((f"/usr/sbin/php-fpm{version}", "-t")),
        exposure=(
            PlanEffect.Kind.LOCAL_SOCKET,
            (
                "No listener or pool changes: every pool keeps its socket, user and settings. "
                "The driver connects only when a site's code opens a connection."
            ),
        ),
        postconditions=(
            f"php-fpm{version} -t accepts the configuration.",
            (
                f"php-fpm{version} -m lists {names}, and each SAPI's conf.d links them to the "
                "distribution's module files."
            ),
            f"{unit} is enabled and active after its reload.",
            "Every reviewed pool listens on its socket.",
        ),
        serves="the distribution's default pool and every site pool",
        socket=socket,
        releases=Releases(f"PHP {version}", "php[0-9]*", prefix, "/etc/php", version),
        startable=False,
        stopped=(
            f"PHP-FPM {version} must be running, since its pools load the driver. Start it "
            f"through ordinary administration, such as sudo systemctl start {unit}, then "
            "prepare again."
        ),
        service=f"{prefix}fpm",
        prerequisites=(f"{prefix}fpm", f"{prefix}cli"),
        prerequisite=(
            f"PHP {version} FPM and CLI are not installed. Prepare and apply the PHP profile "
            "first; a driver plan never installs PHP."
        ),
        pinned=((root,), f"{prefix}common"),
        php_version=version,
        php_supply=supply,
        modules=modules,
        module_list=f"/usr/sbin/php-fpm{version} -m",
        reload=unit,
        maintainer=(
            f"While dpkg runs, the driver's maintainer scripts enable {names} for PHP-FPM and "
            f"the CLI with phpenmod, and PHP-FPM's dpkg trigger restarts {unit}, restarting "
            "every pool's workers."
        ),
        check_failure=(
            f"The driver was installed, but php-fpm{version} -t rejected the configuration "
            "afterwards, so Barectl did not reload PHP-FPM. Barectl does not roll back: "
            "inspect the configuration and the unit's journal, repair it through ordinary "
            "administration, then prepare a new plan."
        ),
        verification_failure=(
            f"The run completed, but the driver's postconditions do not hold: a package is not "
            "installed at its reviewed version, dpkg reports a problem, an earlier package's "
            f"automatic mark changed, php-fpm{version} does not list {names} or a conf.d link "
            "is missing, PHP-FPM is not active, or a reviewed pool's socket is not listening. "
            "Barectl does not repair or roll back; inspect the server through ordinary "
            "administration."
        ),
    )


# docs/wordpress-native-design.md#compatibility-and-supply: the fixed baseline's binary
# packages, each with the module files phpenmod links on both releases (docs/wordpress.md).
WORDPRESS_PACKAGES: Final = (
    ("mysql", (("10-mysqlnd", "mysqlnd"), ("20-mysqli", "mysqli"), ("20-pdo_mysql", "pdo_mysql"))),
    ("curl", (("20-curl", "curl"),)),
    (
        "xml",
        (
            ("15-xml", "xml"),
            ("20-dom", "dom"),
            ("20-simplexml", "simplexml"),
            ("20-xmlreader", "xmlreader"),
            ("20-xmlwriter", "xmlwriter"),
            ("20-xsl", "xsl"),
        ),
    ),
    ("mbstring", (("20-mbstring", "mbstring"),)),
    ("zip", (("20-zip", "zip"),)),
    ("gd", (("20-gd", "gd"),)),
    ("intl", (("20-intl", "intl"),)),
)
# The build's own capabilities WordPress needs, which the baseline's packages cannot add.
WORDPRESS_BUILTINS: Final = ("json", "hash", "fileinfo", "exif")


def php_wordpress(
    release: Release, *, version: str | None = None, supply: str = "ubuntu"
) -> Profile:
    """docs/wordpress.md#php-runtime"""
    version = php_supply.select(release, version, supply)
    prefix = f"php{version}-"
    roots = tuple(f"{prefix}{suffix}" for suffix, _ in WORDPRESS_PACKAGES)
    modules = tuple(module for _, listed in WORDPRESS_PACKAGES for module in listed)
    module_roots = tuple(
        f"{prefix}{suffix}" for suffix, listed in WORDPRESS_PACKAGES for _ in listed
    )
    links = _php_links(version)
    unit = f"php{version}-fpm.service"
    names = ", ".join(module for _, module in modules)
    return Profile(
        Action.PHP_WORDPRESS,
        f"Install the distribution PHP {version} extensions WordPress needs from "
        f"{release.name} packages.",
        roots=roots,
        packages=(
            *roots,
            f"{prefix}common",
            f"{prefix}fpm",
            f"{prefix}cli",
            "php-common",
            "needrestart",
        ),
        units=(unit,),
        trees=(
            TreeSpec(f"/etc/php/{version}/fpm", f"{prefix}fpm", links, rule=SITE_CONVENTION),
            TreeSpec(f"/etc/php/{version}/cli", f"{prefix}cli", links),
            TreeSpec(f"/etc/php/{version}/mods-available", f"{prefix}common", _no_links),
        ),
        ucf=True,
        port=None,
        check=native.Check((f"/usr/sbin/php-fpm{version}", "-t")),
        exposure=(
            PlanEffect.Kind.LOCAL_SOCKET,
            (
                "No listener or pool changes: every pool keeps its socket, user and settings. "
                "No WP-CLI, WordPress, database or certificate is installed."
            ),
        ),
        postconditions=(
            f"php-fpm{version} -t accepts the configuration.",
            (
                f"php-fpm{version} -m and php{version} -m both list {names}, each SAPI's "
                "conf.d links them to the distribution's module files, and the build loads "
                f"{', '.join(WORDPRESS_BUILTINS)}."
            ),
            f"{unit} is enabled and active after its reload.",
            "Every reviewed pool listens on its socket.",
            "The selected site's pool and the selected CLI report the same capabilities.",
        ),
        serves="the distribution's default pool and every site pool",
        socket=f"/run/php/php{version}-fpm.sock",
        releases=Releases(f"PHP {version}", "php[0-9]*", prefix, "/etc/php", version),
        startable=False,
        stopped=(
            f"PHP-FPM {version} must be running, since its pools load the extensions. Start it "
            f"through ordinary administration, such as sudo systemctl start {unit}, then "
            "prepare again."
        ),
        service=f"{prefix}fpm",
        prerequisites=(f"{prefix}fpm", f"{prefix}cli"),
        prerequisite=(
            f"PHP {version} FPM and CLI are not installed. Prepare and apply the PHP profile "
            "first; the WordPress extension plan never installs PHP."
        ),
        pinned=(roots, f"{prefix}common"),
        php_version=version,
        php_supply=supply,
        components=("main", "universe"),
        archives=f"{release.name} archives' main and universe components",
        modules=modules,
        module_roots=module_roots,
        builtins=WORDPRESS_BUILTINS,
        module_list=f"/usr/sbin/php-fpm{version} -m",
        cli_module_list=f"/usr/bin/env -i /usr/bin/php{version} -m",
        reload=unit,
        maintainer=(
            f"While dpkg runs, the packages' maintainer scripts enable {names} for PHP-FPM "
            f"and the CLI with phpenmod, and PHP-FPM's dpkg trigger restarts {unit}, "
            "restarting every pool's workers."
        ),
        check_failure=(
            f"The extensions were installed, but php-fpm{version} -t rejected the configuration "
            "afterwards, so Barectl did not reload PHP-FPM. Barectl does not roll back: "
            "inspect the configuration and the unit's journal, repair it through ordinary "
            "administration, then prepare a new plan."
        ),
        verification_failure=(
            "The run completed, but the WordPress baseline's postconditions do not hold: a "
            "package is not installed at its reviewed version, dpkg reports a problem, an "
            "earlier package's automatic mark changed, php-fpm or the CLI does not list a "
            "baseline capability or a conf.d link is missing, PHP-FPM is not active, or a "
            "reviewed pool's socket is not listening. Barectl does not repair or roll back; "
            "inspect the server through ordinary administration."
        ),
    )


# docs/site-conventions.md#tls-convention: the guarded renewal's override of the service.
CERTBOT_DROP_IN = "/etc/systemd/system/certbot.service.d/barectl.conf"


def certbot(release: Release) -> Profile:
    """docs/tls.md#certbot-renewal-setup: the packages only. Renewal setup, not bootstrap,
    applies it, inhibiting the packaged renewal while the packages install."""
    return Profile(
        Action.CERTBOT,
        f"Install the distribution Certbot {release.certbot} from {release.name} packages and "
        "guard its scheduled renewal.",
        roots=("certbot",),
        packages=("certbot", "python3-certbot", "python3-acme", "needrestart"),
        units=("certbot.service", "certbot.timer"),
        trees=(TreeSpec("/etc/letsencrypt", "certbot", _no_links),),
        ucf=False,
        port=None,
        check=native.Check(("/usr/bin/certbot", "--version"), f"certbot {release.certbot}"),
        exposure=None,
        postconditions=(),
        serves="Certbot's packaged renewal",
        components=("main", "universe"),
        archives=f"{release.name} archives' main and universe components",
        conflicts=(
            "python3-certbot-*",
            "acme-tiny",
            "dehydrated",
            "lego",
            "getssl",
            "uacme",
        ),
        managed_units=False,
        drop_ins=frozenset({CERTBOT_DROP_IN}),
        maintainer_start=(
            "certbot.timer and certbot.service are masked at runtime for the whole run, so "
            "the maintainer scripts can neither enable nor start them: the timer stays "
            "disabled, and nothing renews until the guarded override is verified."
        ),
    )


def source_tools(release: Release) -> Profile:
    return Profile(
        Action.PHP_SOURCE_PREREQUISITES,
        f"Install PHP source verification tools from {release.name} packages.",
        roots=("gpg", "gpg-agent", "curl", "ca-certificates"),
        packages=("gpg", "gpg-agent", "curl", "ca-certificates", "apt", "needrestart"),
        units=(),
        trees=(),
        ucf=False,
        port=None,
        check=native.Check(
            (
                "/usr/bin/sh",
                "-c",
                (
                    "test -x /usr/lib/apt/apt-helper && test -x /usr/bin/gpg && "
                    "test -x /usr/bin/gpg-agent && "
                    "test -x /usr/bin/curl && test -s /etc/ssl/certs/ca-certificates.crt"
                ),
            ),
            limit=1024,
        ),
        exposure=None,
        postconditions=(
            (
                "GnuPG and its agent, the distribution CA bundle and APT's acquisition helper "
                "are available."
            ),
        ),
        serves="PHP source verification tools",
        managed_units=False,
        maintainer=(
            "The distribution's package scripts configure the verification tools and CA bundle."
        ),
        prerequisites=("apt",),
        prerequisite="APT must already be installed by the supported Ubuntu system.",
    )


def php_libraries(release: Release) -> Profile:
    """docs/wordpress-source-qualification.md#core-php-library-prerequisite"""
    return Profile(
        Action.PHP_LIBRARIES,
        f"Install PHP core libraries from {release.name} packages.",
        roots=("libsodium23",),
        packages=("libsodium23", "apt", "needrestart"),
        units=(),
        trees=(),
        ucf=False,
        port=None,
        check=native.Check(
            (
                "/usr/bin/sh",
                "-c",
                "/usr/sbin/ldconfig -p | /usr/bin/grep -q 'libsodium.so.23 '",
            ),
            limit=1024,
        ),
        exposure=None,
        postconditions=("The distribution's Sodium library is installed and available.",),
        serves="PHP core dependencies",
        managed_units=False,
        maintainer="The distribution's package scripts register the shared library.",
        prerequisites=("apt",),
        prerequisite="APT must already be installed by the supported Ubuntu system.",
    )


def wordpress_libraries(release: Release) -> Profile:
    """docs/wordpress-source-qualification.md#distribution-library-prerequisite"""
    return Profile(
        Action.WORDPRESS_LIBRARIES,
        f"Install WordPress extension libraries from {release.name} packages.",
        roots=("libgd3", "libsodium23"),
        packages=("libgd3", "libsodium23", "apt", "needrestart"),
        units=(),
        trees=(),
        ucf=False,
        port=None,
        check=native.Check(
            (
                "/usr/bin/sh",
                "-c",
                (
                    "/usr/sbin/ldconfig -p | /usr/bin/grep -q 'libgd.so.3 ' && "
                    "/usr/sbin/ldconfig -p | /usr/bin/grep -q 'libsodium.so.23 '"
                ),
            ),
            limit=1024,
        ),
        exposure=None,
        postconditions=("The distribution's GD and Sodium libraries are installed and available.",),
        serves="WordPress extension dependencies",
        managed_units=False,
        maintainer="The distribution's package scripts register the shared libraries.",
        prerequisites=("apt",),
        prerequisite="APT must already be installed by the supported Ubuntu system.",
    )


PROFILES = {
    version: {
        profile.action: profile
        for profile in (
            source_tools(release),
            php_libraries(release),
            wordpress_libraries(release),
            nginx(release),
            php(release),
            mariadb(release),
            postgresql(release),
            certbot(release),
            *(php_driver(release, action) for action in DRIVER_ACTIONS),
            php_wordpress(release),
        )
    }
    for version, release in RELEASES.items()
}
PACKAGE_ACTIONS = frozenset(
    {
        Action.NGINX,
        Action.PHP,
        Action.PHP_SOURCE_PREREQUISITES,
        Action.PHP_LIBRARIES,
        Action.WORDPRESS_LIBRARIES,
        Action.MARIADB,
        Action.POSTGRESQL,
        *BRANCH_ACTIONS,
    }
)


def profile(
    release: Release, action: Action, *, version: str | None = None, supply: str = "ubuntu"
) -> Profile:
    if action == Action.PHP:
        return php(release, version=version, supply=supply)
    if action in DRIVER_ACTIONS:
        return php_driver(release, action, version=version, supply=supply)
    if action == Action.PHP_WORDPRESS:
        return php_wordpress(release, version=version, supply=supply)
    if version is not None or supply != "ubuntu":
        raise ValueError("PHP selection cannot be attached to another package profile.")
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
