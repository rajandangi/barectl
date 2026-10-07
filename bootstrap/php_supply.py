"""docs/adr/0016-limit-third-party-php-supply.md"""

from datetime import date

from .releases import Release

ELIGIBLE_BRANCHES = ("8.3", "8.4", "8.5")
SECURITY_END = {
    "8.3": date(2027, 12, 31),
    "8.4": date(2028, 12, 31),
    "8.5": date(2029, 12, 31),
}
SOURCE_URL = "https://packages.sury.org/php/"
PRIMARY_FINGERPRINT = "15058500A0235D97F5D10063B188E2B695BD4743"
KEY_SHA256 = "b486fd5488185c4c46467960fa69c53d5085fec492cf76b9eaf3db33561c9d7c"
KEY_FILE = "/etc/apt/keyrings/sury-php.gpg"
SOURCE_FILE = "/etc/apt/sources.list.d/sury-php.sources"
PREFERENCE_FILE = "/etc/apt/preferences.d/sury-php"


def select(release: Release, version: str | None, supply: str) -> str:
    branch = release.php if version is None else version
    if supply not in {"ubuntu", "sury"}:
        raise ValueError("Unsupported PHP supply.")
    if branch not in ELIGIBLE_BRANCHES or (supply == "ubuntu" and branch != release.php):
        raise ValueError("Unsupported PHP branch for this supply.")
    return branch


def supported(branch: str, on: date) -> bool:
    end = SECURITY_END.get(branch)
    return end is not None and on <= end


def allowed_packages() -> tuple[str, ...]:
    return (
        "php-common",
        *(
            f"php{branch}-{suffix}"
            for branch in ELIGIBLE_BRANCHES
            for suffix in ("fpm", "cli", "common", "readline", "mysql", "pgsql", "opcache")
            if branch != "8.5" or suffix != "opcache"
        ),
    )


def source_content(release: Release, architecture: str) -> str:
    if architecture not in {"amd64", "arm64"}:
        raise ValueError("Unsupported PHP source architecture.")
    return (
        "Types: deb\n"
        f"URIs: {SOURCE_URL}\n"
        f"Suites: {release.codename}\n"
        "Components: main\n"
        f"Architectures: {architecture}\n"
        f"Signed-By: {KEY_FILE} {PRIMARY_FINGERPRINT}\n"
        "Check-Valid-Until: yes\n"
        "Valid-Until-Max: 604800\n"
    )


def preference_content(release: Release) -> str:
    pin = f"Pin: release o=deb.sury.org,n={release.codename}\n"
    return (
        "Package: *\n" + pin + "Pin-Priority: -1\n\n"
        "Package: " + " ".join(allowed_packages()) + "\n" + pin + "Pin-Priority: 700\n"
    )


def qualified(release: Release, architecture: str, branch: str, supply: str) -> bool:
    """docs/php-versions.md#qualification-and-delivery-gates"""
    return architecture in {"amd64", "arm64"} and (
        (supply == "sury" and branch in ELIGIBLE_BRANCHES)
        or (supply == "ubuntu" and branch == release.php)
    )
