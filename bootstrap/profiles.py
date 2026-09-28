"""The supported bootstrap profiles and maintenance action, and their tested baselines.

A profile names its root packages, the packages whose state is evidence, its service
units and configuration directories with their distribution-default contents, and the
listener it exposes. Everything here describes Ubuntu 24.04's own packages, as recorded
on the disposable acceptance server (docs/ssh-connections.md#plan-preparation); it is
not a general package list.
Changing a profile's definition changes its revision, so plans record which one they were
reviewed against.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from .models import Action

# Revision of every definition below. Increase it whenever one changes.
PROFILE_REVISION = 1
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
)
PROFILES = {profile.action: profile for profile in (NGINX, PHP)}
METADATA_REFRESH_INTENT = "Refresh the authenticated package indexes from the configured sources."
CLEAR_RESULTS_INTENT = "Clear finished bootstrap runs that the server's systemd retains."

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
}
# What each admitted hook does to native caches, for the metadata refresh review.
HOOK_EFFECTS = {
    "apt": "records the update-success stamp in /var/lib/apt/periodic",
    "command-not-found": "rebuilds the command-not-found database",
    "update-notifier-common": "refreshes the login message's available-updates count",
    "ubuntu-pro-client": "starts Ubuntu Pro's apt-news and esm-cache services when run as root",
    "debconf": "preconfigures packages with debconf before dpkg unpacks them",
    "needrestart": "checks for services that use outdated libraries after dpkg runs",
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
