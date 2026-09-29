"""docs/adr/0008-review-each-ubuntu-release-by-its-own-policy.md"""

import re
from collections.abc import Mapping
from dataclasses import dataclass

from discovery import releases as supported

from .evidence import IndexTarget, OsRelease


@dataclass(frozen=True)
class Release:
    # /etc/os-release's VERSION_ID, such as "24.04".
    version: str
    codename: str
    # The APT and systemd series qualified on this release.
    apt: str
    systemd: str
    # The PHP version the release's php-defaults package selects, such as "8.3".
    php: str
    # The PHP packages besides FPM, CLI and their common files that the release's PHP FPM
    # and CLI depend on, such as PHP 8.3's separate OPcache extension.
    php_extras: tuple[str, ...]
    # The APT hooks the release's own packages install, by effective configuration key (as
    # APT compares keys, in lower case) and value, with the package that installs each.
    hooks: Mapping[tuple[str, str], str]

    @property
    def name(self) -> str:
        return f"Ubuntu {self.version}"

    @property
    def suites(self) -> tuple[str, str, str]:
        return (self.codename, f"{self.codename}-updates", f"{self.codename}-security")

    @property
    def backports(self) -> str:
        return f"{self.codename}-backports"

    def owns(self, target: IndexTarget) -> bool:
        """docs/adr/0008-review-each-ubuntu-release-by-its-own-policy.md#hosting-providers-images"""
        return (
            target.origin == "Ubuntu"
            and target.codename == self.codename
            and target.suite in {*self.suites, self.backports}
        )

    @property
    def origins(self) -> frozenset[str]:
        """As APT's simulation names them, such as ``Ubuntu:24.04/noble-updates``."""
        return frozenset(f"Ubuntu:{self.version}/{suite}" for suite in self.suites)

    def qualifies(self, package: str, version: str) -> bool:
        series = {"apt": self.apt, "systemd": self.systemd}[package]
        return re.match(rf"{re.escape(series)}(\.|-|\Z)", version) is not None


# PackageKit's hook, which it installs for dpkg runs and for index updates alike.
_PACKAGEKIT_NOBLE = (
    "/usr/bin/test -e /usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service "
    "&& /usr/bin/test -S /var/run/dbus/system_bus_socket && /usr/bin/gdbus call --system "
    "--dest org.freedesktop.PackageKit --object-path /org/freedesktop/PackageKit --timeout 4 "
    "--method org.freedesktop.PackageKit.StateHasChanged cache-update > /dev/null; "
    "/bin/echo > /dev/null"
)
# PackageKit 1.3's hook also skips OSTree-booted systems.
_PACKAGEKIT_RESOLUTE = _PACKAGEKIT_NOBLE.replace(
    "&& /usr/bin/gdbus", "&& /usr/bin/test ! -e /run/ostree-booted && /usr/bin/gdbus"
)
# docs/ssh-connections.md#plan-preparation
_COMMON_HOOKS = {
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
    # Installed on Ubuntu's official server cloud images.
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


def _with_packagekit(hook: str) -> dict[tuple[str, str], str]:
    return {
        **_COMMON_HOOKS,
        ("dpkg::post-invoke", hook): "packagekit",
        ("apt::update::post-invoke-success", hook): "packagekit",
    }


NOBLE = Release(
    version=supported.NOBLE.version,
    codename=supported.NOBLE.codename,
    apt="2.8",
    systemd="255",
    php=supported.NOBLE.php,
    php_extras=("php8.3-opcache", "php8.3-readline"),
    hooks=_with_packagekit(_PACKAGEKIT_NOBLE),
)
# Hosting providers' 26.04 images install ubuntu-helper-virt-hwe:
# docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#consequences
_VIRT_HOOKS = {
    (
        "dpkg::pre-install-pkgs",
        "test -x /usr/bin/apt_hook_ubuntu_virt && /usr/bin/apt_hook_ubuntu_virt || true",
    ): "ubuntu-helper-virt-hwe",
    (
        "dpkg::tools::options::/usr/bin/apt_hook_ubuntu_virt::version",
        "2",
    ): "ubuntu-helper-virt-hwe",
}
RESOLUTE = Release(
    version=supported.RESOLUTE.version,
    codename=supported.RESOLUTE.codename,
    apt="3.2",
    systemd="259",
    php=supported.RESOLUTE.php,
    # PHP 8.5 builds OPcache in; it has no separate package.
    php_extras=("php8.5-readline",),
    hooks={**_with_packagekit(_PACKAGEKIT_RESOLUTE), **_VIRT_HOOKS},
)
RELEASES = {release.version: release for release in (NOBLE, RESOLUTE)}
# The dpkg architectures whose packages are supported on every release.
ARCHITECTURES = frozenset({"amd64", "arm64"})


def of(os: OsRelease) -> Release | None:
    return RELEASES.get(os.version_id) if os.id == "ubuntu" else None


def named() -> str:
    """The supported releases as the pages name them, such as "Ubuntu 24.04 and 26.04"."""
    versions = [release.version for release in RELEASES.values()]
    return f"Ubuntu {', '.join(versions[:-1])} and {versions[-1]}"
