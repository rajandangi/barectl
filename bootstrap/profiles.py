"""docs/adr/0008-review-each-ubuntu-release-by-its-own-policy.md"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from . import native
from .models import Action
from .releases import RELEASES, Release

# Increase whenever any definition below changes.
PROFILE_REVISION = 4
HTTP_PORT = 80
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


def nginx(release: Release) -> Profile:
    return Profile(
        Action.NGINX,
        f"Install the distribution-default Nginx web server from {release.name} packages.",
        roots=("nginx",),
        packages=("nginx", "nginx-common", "needrestart"),
        units=("nginx.service",),
        trees=(TreeSpec("/etc/nginx", "nginx-common", _nginx_links),),
        ucf=False,
        port=HTTP_PORT,
        check="/usr/sbin/nginx -t -q",
    )


def php(release: Release) -> Profile:
    version = release.php
    prefix = f"php{version}-"
    links = _php_links(version)
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
        units=(f"php{version}-fpm.service",),
        trees=(
            TreeSpec(f"/etc/php/{version}/fpm", f"{prefix}fpm", links),
            TreeSpec(f"/etc/php/{version}/cli", f"{prefix}cli", links),
            TreeSpec(f"/etc/php/{version}/mods-available", f"{prefix}common", _no_links),
        ),
        ucf=True,
        port=None,
        check=f"/usr/sbin/php-fpm{version} -t",
        socket=f"/run/php/php{version}-fpm.sock",
        releases=Releases(f"PHP {version}", "php[0-9]*", prefix, "/etc/php", version),
        runtime=Runtime(f"php{version} -v", f"{prefix}cli", "PHP {version} (cli) "),
    )


PROFILES = {
    version: {profile.action: profile for profile in (nginx(release), php(release))}
    for version, release in RELEASES.items()
}
PACKAGE_ACTIONS = frozenset({Action.NGINX, Action.PHP})


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
