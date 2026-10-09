"""The combinations WordPress is qualified on (docs/v0.4-qualification.md#supported-combinations).

A combination is a supported Ubuntu release with its own PHP branch from Ubuntu packages and
its default MariaDB series, on one architecture. The reviews that would install, finish,
inspect or maintain an application refuse any combination not listed as qualified here, and
the dashboard shows the whole matrix so an operator sees which combinations have evidence.
An architecture is enabled only where the qualification record holds evidence for it: arm64 on
its local aarch64 runs at the revision the record names, amd64 not at all because no x86_64
run exists. Native statuses on an exact published revision are recorded separately.
"""

from dataclasses import dataclass

from discovery.releases import NOBLE, RESOLUTE, SupportedRelease

ARCHITECTURES = ("amd64", "arm64")


@dataclass(frozen=True)
class Combination:
    release: SupportedRelease
    architecture: str
    qualified: bool
    # Why a combination is not enabled, or where its evidence was recorded.
    evidence: str

    @property
    def php(self) -> str:
        return self.release.php

    @property
    def mariadb(self) -> str:
        return self.release.mariadb

    @property
    def label(self) -> str:
        return f"{self.release.name}, PHP {self.php}, MariaDB {self.mariadb}, {self.architecture}"


_LOCAL = "The disposable-server suites passed on aarch64 containers."
_PENDING = (
    "No native run on this architecture is recorded for an exact published revision, so it "
    "stays disabled."
)

COMBINATIONS = (
    Combination(NOBLE, "arm64", True, _LOCAL),
    Combination(NOBLE, "amd64", False, _PENDING),
    Combination(RESOLUTE, "arm64", True, _LOCAL),
    Combination(RESOLUTE, "amd64", False, _PENDING),
)


def combination(version: str, architecture: str) -> Combination | None:
    return next(
        (
            item
            for item in COMBINATIONS
            if item.release.version == version and item.architecture == architecture
        ),
        None,
    )


def qualified(version: str, architecture: str, php: str, supply: str) -> bool:
    """Whether a site's release, architecture and PHP selection is a qualified combination."""
    found = combination(version, architecture)
    return found is not None and found.qualified and supply == "ubuntu" and php == found.php


def reason(version: str, architecture: str, php: str, supply: str) -> str:
    """Why a combination is not qualified, in the words a refusal shows."""
    found = combination(version, architecture)
    if supply != "ubuntu" or found is None or php != found.php:
        return (
            f"WordPress with PHP {php} from {supply} packages on Ubuntu {version} "
            f"({architecture}) has not completed Barectl's qualification. Only the release's "
            "own PHP branch from Ubuntu packages, on an architecture the supported "
            "combinations list, is qualified, and Barectl does not change the site's PHP "
            "selection."
        )
    return (
        f"WordPress on {found.label} is not qualified. {found.evidence} "
        "See the supported combinations in docs/v0.4-qualification.md."
    )


_UNAME = {"x86_64": "amd64", "aarch64": "arm64"}


def architecture_of(machine: str) -> str:
    """The package architecture of ``uname -m``'s machine name, empty when unrecognized."""
    return _UNAME.get(machine, "")
