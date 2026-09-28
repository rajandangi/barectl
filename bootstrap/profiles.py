"""The supported bootstrap profiles and maintenance action, and their tested baselines.

A profile names its root packages, the packages whose state is evidence, its service
units and configuration directories with their distribution-default contents, the other
releases of its software it cannot coexist with, the listener it exposes, and how its
installation is checked afterwards. Everything here describes Ubuntu 24.04's own packages,
as recorded on the disposable acceptance server (docs/ssh-connections.md#plan-preparation);
it is not a general package list.
Changing a profile's definition changes its revision, so plans record which one they were
reviewed against.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from . import native
from .models import Action

# Revision of every definition below. Increase it whenever one changes.
PROFILE_REVISION = 3
HTTP_PORT = 80
# The command apply runs submit their transient systemd service through (ADR 0006).
APPLY_ENTRYPOINT = "/usr/bin/systemd-run"
SUPPORTED_OS = ("ubuntu", "24.04")
# The dpkg architectures whose Ubuntu 24.04 packages are supported. Acceptance names the
# architectures it exercised; package availability alone is not qualification.
ARCHITECTURES = frozenset({"amd64", "arm64"})
# The archives a reviewed transaction may install from, as APT's simulation names them.
ALLOWED_ORIGINS = frozenset(
    {"Ubuntu:24.04/noble", "Ubuntu:24.04/noble-updates", "Ubuntu:24.04/noble-security"}
)
# The suites whose authenticated indexes a package plan needs.
REQUIRED_SUITES = ("noble", "noble-updates", "noble-security")

type LinkRule = Callable[[str, str], bool]


@dataclass(frozen=True)
class TreeSpec:
    """A configuration directory owned by one package, with the links it may contain."""

    root: str
    # The package whose installation creates the directory. Without it, the directory must
    # not exist: anything there is leftover or custom configuration.
    owner: str
    links: LinkRule


@dataclass(frozen=True)
class Releases:
    """The releases of a profile's software that share its package names and directories.

    Only the profile's own release is supported: another release's installed packages or
    configuration refuse the profile, as does anything else in the directory holding every
    release's configuration.
    """

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
    # The service's own syntax check, which an apply run runs as root after its changes.
    check: str
    # The local socket the distribution's default configuration listens on, if any.
    socket: str | None = None
    releases: Releases | None = None
    runtime: Runtime | None = None

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
    def revalidation(self) -> str:
        """The package digest a plan records and its apply payload recomputes."""
        return native.package_digest(
            self.units,
            tuple(spec.root for spec in self.trees),
            self.port,
            ucf=self.ucf,
            listings=tuple(self.layout),
            socket=self.socket,
        )


def _nginx_links(path: str, target: str) -> bool:
    if path == "/etc/nginx/sites-enabled/default":
        return target == "/etc/nginx/sites-available/default"
    module = re.fullmatch(r"/etc/nginx/modules-enabled/[0-9]{2}-mod-([a-z0-9-]+)\.conf", path)
    return module is not None and target == (
        f"/usr/share/nginx/modules-available/mod-{module[1]}.conf"
    )


def _php_links(path: str, target: str) -> bool:
    module = re.fullmatch(r"/etc/php/8\.3/(?:fpm|cli)/conf\.d/[0-9]{2}-([a-z0-9_]+)\.ini", path)
    return module is not None and target == f"/etc/php/8.3/mods-available/{module[1]}.ini"


def _no_links(_path: str, _target: str) -> bool:
    return False


NGINX = Profile(
    Action.NGINX,
    "Install the distribution-default Nginx web server from Ubuntu 24.04 packages.",
    roots=("nginx",),
    packages=("nginx", "nginx-common", "needrestart"),
    units=("nginx.service",),
    trees=(TreeSpec("/etc/nginx", "nginx-common", _nginx_links),),
    ucf=False,
    port=HTTP_PORT,
    check="/usr/sbin/nginx -t -q",
)
PHP = Profile(
    Action.PHP,
    "Install the distribution-default PHP 8.3 FPM and CLI from Ubuntu 24.04 packages.",
    roots=("php8.3-fpm", "php8.3-cli"),
    packages=(
        "php8.3-fpm",
        "php8.3-cli",
        "php8.3-common",
        "php8.3-opcache",
        "php8.3-readline",
        "php-common",
        "needrestart",
    ),
    units=("php8.3-fpm.service",),
    trees=(
        TreeSpec("/etc/php/8.3/fpm", "php8.3-fpm", _php_links),
        TreeSpec("/etc/php/8.3/cli", "php8.3-cli", _php_links),
        TreeSpec("/etc/php/8.3/mods-available", "php8.3-common", _no_links),
    ),
    ucf=True,
    port=None,
    check="/usr/sbin/php-fpm8.3 -t",
    socket="/run/php/php8.3-fpm.sock",
    releases=Releases("PHP 8.3", "php[0-9]*", "php8.3-", "/etc/php", "8.3"),
    runtime=Runtime("php8.3 -v", "php8.3-cli", "PHP {version} (cli) "),
)
PROFILES = {profile.action: profile for profile in (NGINX, PHP)}
METADATA_REFRESH_INTENT = "Refresh the authenticated package indexes from the configured sources."
CLEAR_RESULTS_INTENT = "Clear finished bootstrap runs that the server's systemd retains."

# PackageKit's hook, which it installs for dpkg runs and for index updates alike.
_PACKAGEKIT_HOOK = (
    "/usr/bin/test -e /usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service "
    "&& /usr/bin/test -S /var/run/dbus/system_bus_socket && /usr/bin/gdbus call --system "
    "--dest org.freedesktop.PackageKit --object-path /org/freedesktop/PackageKit --timeout 4 "
    "--method org.freedesktop.PackageKit.StateHasChanged cache-update > /dev/null; "
    "/bin/echo > /dev/null"
)
# APT hooks that Ubuntu 24.04 packages install, by effective configuration key (as APT
# compares keys, in lower case) and value, with the package that installs each. These are
# the only hooks admitted; any other hook, or a changed one, refuses the plan. Recorded
# from `apt-config dump` on the disposable acceptance server.
DISTRIBUTION_HOOKS = {
    ("dpkg::pre-install-pkgs", "/usr/sbin/dpkg-preconfigure --apt || true"): "debconf",
    (
        "dpkg::post-invoke",
        (
            "test -x /usr/lib/needrestart/apt-pinvoke && /usr/lib/needrestart/apt-pinvoke "
            "-m u || true"
        ),
    ): "needrestart",
    (
        "dpkg::post-invoke",
        (
            "if [ -d /var/lib/update-notifier ]; then touch "
            "/var/lib/update-notifier/dpkg-run-stamp; fi; "
            "/usr/lib/update-notifier/update-motd-updates-available 2>/dev/null || true"
        ),
    ): "update-notifier-common",
    (
        "apt::update::post-invoke-success",
        "touch /var/lib/apt/periodic/update-success-stamp 2>/dev/null || true",
    ): "apt",
    (
        "apt::update::post-invoke-success",
        (
            "if /usr/bin/test -w /var/lib/command-not-found/ -a -e /usr/lib/cnf-update-db; then "
            "/usr/lib/cnf-update-db > /dev/null; fi"
        ),
    ): "command-not-found",
    (
        "apt::update::post-invoke-success",
        "/usr/lib/update-notifier/update-motd-updates-available 2>/dev/null || true",
    ): "update-notifier-common",
    (
        "apt::update::pre-invoke",
        (
            "[ ! -e /run/systemd/system ] || [ $(id -u) -ne 0 ] || systemctl start --no-block "
            "apt-news.service esm-cache.service >/dev/null 2>&1 || true"
        ),
    ): "ubuntu-pro-client",
    (
        "binary::apt::aptcli::hooks::upgrade",
        (
            "[ ! -f /usr/lib/ubuntu-advantage/apt-esm-json-hook ] || [ $(id -u) -ne 0 ] || "
            "/usr/lib/ubuntu-advantage/apt-esm-json-hook 2>> /var/log/ubuntu-advantage-apt-hook.log"
            " || true"
        ),
    ): "ubuntu-pro-client",
    # Also installed on Ubuntu's official 24.04 server cloud image, recorded from
    # `apt-config dump` on the reboot qualification's virtual machine. None of them runs
    # before dpkg; snapd's runs only for the apt command, never for apt-get.
    ("dpkg::post-invoke", _PACKAGEKIT_HOOK): "packagekit",
    ("apt::update::post-invoke-success", _PACKAGEKIT_HOOK): "packagekit",
    (
        "apt::update::post-invoke-success",
        (
            "if /usr/bin/test -w /var/cache/swcatalog -a -e /usr/bin/appstreamcli; then "
            "appstreamcli refresh --source=os > /dev/null || true; fi"
        ),
    ): "appstream",
    (
        "binary::apt::aptcli::hooks::install",
        "[ ! -f /usr/bin/snap ] || /usr/bin/snap advise-snap --from-apt 2>/dev/null || true",
    ): "snapd",
}
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
