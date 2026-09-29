"""Configuration collections: Nginx site files and PHP-FPM pools.

docs/adr/0001-configuration-observations-depend-on-package-observation.md
"""

import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Protocol

from ..models import ObservationOutcome
from ..snapshot import (
    Observation,
    Package,
    PoolEntryObservation,
    SiteFileObservation,
    WebStackComponentObservation,
)
from ..ssh import RemoteShell
from .components import PACKAGE_QUERY, _observe_installed
from .parsers import (
    NginxReferences,
    _fpm_includes,
    _nginx_http_includes,
    fpm_main_extras,
    nginx_main_extras,
    nginx_references,
    parse_nginx_site,
    parse_pool_file,
    parse_pool_sections,
)
from .probes import (
    _OUTSIDE_LAYOUT,
    _bounded,
    _Failed,
    _list_directory,
    _outside_layout,
    _overall,
    _read_file,
)

# docs/ssh-connections.md#nginx-site-file-and-php-fpm-pool-observations
SITES_ENABLED_DIR = "/etc/nginx/sites-enabled"
PHP_BASE_DIR = "/etc/php"
POOL_SUBPATH = "fpm/pool.d"
# The main configuration files and the include directives with which the Debian packages
# load those directories.
# https://nginx.org/en/docs/ngx_core_module.html#include
# https://www.php.net/manual/en/install.fpm.configuration.php
NGINX_CONF = "/etc/nginx/nginx.conf"
SITES_INCLUDE = f"{SITES_ENABLED_DIR}/*"
# The includes the packaged nginx.conf declares, by enclosing block
# (docs/ssh-connections.md#site-observations).
NGINX_PACKAGED = frozenset(
    {
        ("", "/etc/nginx/modules-enabled/*.conf"),
        ("http", "/etc/nginx/mime.types"),
        ("http", "/etc/nginx/conf.d/*.conf"),
        ("http", SITES_INCLUDE),
    }
)
FPM_CONF_SUBPATH = "fpm/php-fpm.conf"
# Entries of the site directory; nginx includes every entry it holds.
SITE_ENTRY = re.compile(r"[A-Za-z0-9._-]{1,100}")
# Versioned PHP-FPM packages, such as "php8.3-fpm", name the PHP version they configure.
PHP_FPM_PACKAGE = re.compile(r"php([0-9]+(?:\.[0-9]+)*)-fpm")
# Pool configuration files; PHP-FPM's pool.d include matches *.conf only.
POOL_FILE = re.compile(r"[A-Za-z0-9._-]{1,95}\.conf")
MAX_SITES = 200
MAX_VERSIONS = 20
MAX_POOLS = 200
# The FastCGI parameters nginx-common installs, the one include site reconstruction
# interprets once it confirms the packaged bytes (docs/ssh-connections.md#site-observations).
PACKAGED_FASTCGI = "fastcgi.conf"


def _collection_warning(
    status: ObservationOutcome,
    warnings: Sequence[str],
    explanations: dict[ObservationOutcome, str],
    *,
    empty: bool,
) -> str:
    """The collection's warning: why it has its outcome, then what was skipped or refused."""
    parts = list(warnings)
    if status != ObservationOutcome.OBSERVED:
        parts.insert(0, explanations[status])
    elif empty:
        parts.append(explanations[status])
    return " ".join(parts)


class _Entry(Protocol):
    @property
    def outcome(self) -> ObservationOutcome: ...


@dataclass
class _Collection[E: _Entry]:
    """A configuration collection read from one or more Debian configuration directories.

    Nginx site files and PHP-FPM pools are both read here, so confirming the include,
    listing the directory, reading a listed entry, the cap and the collection's outcome,
    warning and source follow one rule.
    """

    shell: RemoteShell
    # Why the collection has each outcome, put before or after the other warnings once
    # Barectl listed a directory. Until then the failed read explains the outcome itself.
    explanations: dict[ObservationOutcome, str]
    cap: int
    cap_warning: str
    entries: list[E] = field(default_factory=list)
    _warnings: list[str] = field(default_factory=list)
    # Outcomes of the reads that yielded no entries, such as an unreadable directory.
    _outcomes: list[ObservationOutcome] = field(default_factory=list)
    # The reads that decided the collection's outcome, in order. They are its source.
    _reads: list[str] = field(default_factory=list)
    # Whether Barectl read a listing, and whether any listing named an entry to read. A
    # collection whose listings named nothing is observed empty; one whose named entries
    # all turn out not to exist is absent.
    _listed: bool = False
    _named: bool = False
    _capped: bool = False
    # Listed entries whose names Barectl does not interpret.
    _skipped: bool = False
    # Why each directory Barectl tried to list could not be listed.
    unlisted: dict[str, _Failed] = field(default_factory=dict)

    def warn(self, message: str) -> None:
        _bounded(self._warnings, message)

    def fail(self, failure: _Failed) -> None:
        """Record a read that yielded no entries, adding it to the collection's source."""
        self._reads.append(failure.source)
        self._outcomes.append(failure.status)
        self.warn(failure.warning)

    def add(self, entry: E) -> None:
        if len(self.entries) >= self.cap:
            self._capped = True
            self.warn(self.cap_warning)
            return
        self.entries.append(entry)

    def each[T](self, items: Iterable[T]) -> Iterator[T]:
        """``items`` in order, until the collection holds more entries than it keeps."""
        for item in items:
            if self._capped:
                return
            yield item

    def confirm_include(
        self, path: str, includes: Callable[[str], set[str] | None], wanted: str
    ) -> _Failed | str:
        """The main configuration file at ``path`` when it includes ``wanted``, else why not."""
        confirmed = _includes_confirmed(self.shell, path, includes, wanted)
        if isinstance(confirmed, _Failed):
            self.fail(confirmed)
        return confirmed

    @property
    def listed(self) -> bool:
        return self._listed

    @property
    def fully_listed(self) -> bool:
        """Whether every directory was listed and each entry it holds is among the entries."""
        return self._listed and not (self._outcomes or self._capped or self._skipped)

    def gap(self, unread: ObservationOutcome) -> ObservationOutcome | None:
        """Why the collection may miss something its component loads, or ``None``.

        Inaccessible when only the SSH user's permissions hid entries, unsupported for
        anything else, and ``unread`` when Barectl listed nothing.
        """
        missed = {*self._outcomes, *(entry.outcome for entry in self.entries)} - {
            ObservationOutcome.OBSERVED,
            ObservationOutcome.ABSENT,
        }
        if self._capped or self._skipped:
            return ObservationOutcome.UNSUPPORTED
        if missed:
            return (
                ObservationOutcome.INACCESSIBLE
                if missed == {ObservationOutcome.INACCESSIBLE}
                else ObservationOutcome.UNSUPPORTED
            )
        return None if self._listed else unread

    def listing(self, directory: str, pattern: re.Pattern[str], skipped: str) -> Iterator[str]:
        """The names in ``directory`` that match ``pattern``, until the collection is full.

        ``skipped`` is the warning for entries that do not match, with ``{count}`` in
        place of their number.
        """
        self._reads.append(directory)
        listed = _list_directory(self.shell, directory)
        if isinstance(listed, _Failed):
            self.unlisted[directory] = _outside_layout(listed)
            self.fail(self.unlisted[directory])
            return iter(())
        self._listed = True
        names = [entry for entry in listed if pattern.fullmatch(entry)]
        self._named = self._named or bool(names)
        if count := len(listed) - len(names):
            self._skipped = True
            self.warn(skipped.format(count=count))
        return self.each(names)

    def read(self, path: str) -> str | _Failed:
        """A listed entry that does not exist, such as a broken symlink, is absent."""
        text = _read_file(self.shell, path)
        if isinstance(text, _Failed) and text.missing:
            return replace(text, status=ObservationOutcome.ABSENT)
        return text

    def observation(self) -> Observation[tuple[E, ...]]:
        outcomes = [*self._outcomes, *(entry.outcome for entry in self.entries)]
        status = _overall(outcomes, listed_empty=self._listed and not self._named)
        if self._listed:
            warning = _collection_warning(
                status, self._warnings, self.explanations, empty=not self.entries
            )
        else:
            warning = " ".join(self._warnings)
        return Observation(status, tuple(dict.fromkeys(self._reads)), warning, tuple(self.entries))


def _includes_confirmed(
    shell: RemoteShell, path: str, includes: Callable[[str], set[str] | None], wanted: str
) -> _Failed | str:
    """The main configuration file at ``path`` when it includes ``wanted``, else why not.

    ``includes`` returns the include values the file declares where they load
    configuration, or ``None`` when the file is not in a supported form.
    """
    text = _read_file(shell, path)
    if isinstance(text, _Failed):
        return _outside_layout(text)
    declared = includes(text)
    if declared is None:
        return _Failed(
            ObservationOutcome.UNSUPPORTED,
            f"{path} is not in a supported configuration format, so Barectl cannot confirm "
            f"that it includes {wanted}.",
            path,
        )
    if wanted not in declared:
        return _Failed(
            ObservationOutcome.UNSUPPORTED,
            f"{path} does not include {wanted}, so Barectl cannot confirm which files it "
            f"loads. {_OUTSIDE_LAYOUT}",
            path,
        )
    return text


_SITES_EXPLANATIONS = {
    ObservationOutcome.OBSERVED: f"No site configuration files are listed in {SITES_ENABLED_DIR}.",
    ObservationOutcome.ABSENT: f"None of the entries listed in {SITES_ENABLED_DIR} exist.",
    ObservationOutcome.INACCESSIBLE: (
        "The SSH user cannot read the site configuration files. Barectl does not use sudo."
    ),
    ObservationOutcome.UNSUPPORTED: (
        f"No file in {SITES_ENABLED_DIR} could be read as a supported Nginx site configuration."
    ),
}


_SITES_CAP = (
    f"{SITES_ENABLED_DIR} holds more site entries than Barectl shows. Only the first "
    f"{MAX_SITES} are shown."
)


@dataclass(frozen=True)
class EnabledSites:
    """The Nginx site file observation, with what site reconstruction compares against it."""

    observation: Observation[tuple[SiteFileObservation, ...]]
    # The paths and FastCGI endpoints of each observed site file, by entry name.
    references: Mapping[str, NginxReferences]
    # What nginx.conf declares beyond the packaged includes, where server blocks may hide.
    main_extras: tuple[str, ...]
    # The directory was listed; fully when every entry it holds is among the entries.
    listed: bool
    fully_listed: bool


def _collect_nginx_sites(shell: RemoteShell, nginx: WebStackComponentObservation) -> EnabledSites:
    found = _Collection[SiteFileObservation](shell, _SITES_EXPLANATIONS, MAX_SITES, _SITES_CAP)
    references: dict[str, NginxReferences] = {}
    extras: list[str] = []
    observation = _observe_installed(
        nginx.package, lambda _packages: _observe_sites(found, references, extras)
    )
    return EnabledSites(observation, references, tuple(extras), found.listed, found.fully_listed)


def _observe_sites(
    found: _Collection[SiteFileObservation],
    references: dict[str, NginxReferences],
    extras: list[str],
) -> Observation[tuple[SiteFileObservation, ...]]:
    confirmed = found.confirm_include(NGINX_CONF, _nginx_http_includes, SITES_INCLUDE)
    if isinstance(confirmed, str):
        declared = nginx_main_extras(confirmed, NGINX_PACKAGED)
        extras.extend(("a form Barectl does not interpret",) if declared is None else declared)
        names = found.listing(
            SITES_ENABLED_DIR,
            SITE_ENTRY,
            f"{SITES_ENABLED_DIR} lists {{count}} entries whose names Barectl does not "
            "interpret. They were skipped.",
        )
        # An observed site file's own warning, about included files Barectl skips, stays
        # on it.
        for name in names:
            found.add(_observe_site(found, name, references))
    return found.observation()


def _observe_site(
    found: _Collection[SiteFileObservation], name: str, references: dict[str, NginxReferences]
) -> SiteFileObservation:
    path = f"{SITES_ENABLED_DIR}/{name}"
    text = found.read(path)
    if isinstance(text, _Failed):
        return SiteFileObservation(name, text.status, (), (), path, text.warning)
    parsed = parse_nginx_site(text)
    referenced = nginx_references(text, frozenset({PACKAGED_FASTCGI}))
    if parsed is not None and referenced is not None:
        references[name] = referenced
    if parsed is None:
        return SiteFileObservation(
            name,
            ObservationOutcome.UNSUPPORTED,
            (),
            (),
            path,
            f"{path} does not define a supported Nginx site configuration. Only its "
            "server blocks' server_name and listen directives are read.",
        )
    warning = (
        f"{path} includes other configuration files. Barectl does not read them, so server "
        "names and listen addresses they declare are not shown."
        if parsed.includes
        else ""
    )
    return SiteFileObservation(
        name, ObservationOutcome.OBSERVED, parsed.server_names, parsed.listens, path, warning
    )


_POOLS_EXPLANATIONS = {
    ObservationOutcome.OBSERVED: f"No PHP-FPM pools are configured under {PHP_BASE_DIR}.",
    ObservationOutcome.ABSENT: (
        f"None of the PHP-FPM pool files listed under {PHP_BASE_DIR} exist."
    ),
    ObservationOutcome.INACCESSIBLE: (
        "The SSH user cannot read the PHP-FPM pool configuration. Barectl does not use sudo."
    ),
    ObservationOutcome.UNSUPPORTED: (
        f"No PHP-FPM pool configuration under {PHP_BASE_DIR} could be read in a supported form."
    ),
}
_POOL_CAP = f"More than {MAX_POOLS} PHP-FPM pools were found. The rest were skipped."


_Pools = _Collection[PoolEntryObservation]


def _add_pool(found: _Pools, row: PoolEntryObservation, directory: str) -> None:
    for index, pool in enumerate(found.entries):
        if pool.version == row.version and pool.name.casefold() == row.name.casefold():
            # PHP-FPM merges repeated pool sections; Barectl does not guess the result.
            found.entries[index] = replace(
                pool,
                outcome=ObservationOutcome.UNSUPPORTED,
                listen="",
                warning=(
                    f"Pool {pool.name} is declared more than once under {directory}. "
                    "PHP-FPM merges the declarations; Barectl does not, so its listen "
                    "address is not shown."
                ),
            )
            return
    found.add(row)


@dataclass(frozen=True)
class FpmPools:
    """The PHP-FPM pool observation, with what site reconstruction compares against it."""

    observation: Observation[tuple[PoolEntryObservation, ...]]
    # Why a version's pool directory was not read.
    unread: Mapping[str, _Failed]
    # Why a pool of an installed version may be missing, or ``None`` if none can be.
    gap: ObservationOutcome | None
    # What each version's php-fpm.conf declares beyond its pool directory's include.
    main_extras: Mapping[str, tuple[str, ...]]
    # The user each pool runs as, by PHP version and pool name.
    users: Mapping[tuple[str, str], str]


@dataclass
class _PoolReads:
    unread: dict[str, _Failed] = field(default_factory=dict)
    main_extras: dict[str, tuple[str, ...]] = field(default_factory=dict)
    users: dict[tuple[str, str], str] = field(default_factory=dict)
    # A pool file includes others, or versions were skipped: pools may be missing.
    incomplete: bool = False


def _collect_pools_of_version(found: _Pools, version: str, reads: _PoolReads) -> None:
    directory = f"{PHP_BASE_DIR}/{version}/{POOL_SUBPATH}"
    config_path = f"{PHP_BASE_DIR}/{version}/{FPM_CONF_SUBPATH}"
    confirmed = found.confirm_include(config_path, _fpm_includes, f"{directory}/*.conf")
    if isinstance(confirmed, _Failed):
        reads.unread[version] = confirmed
        return
    extras = fpm_main_extras(confirmed, f"{directory}/*.conf")
    reads.main_extras[version] = (
        ("a form Barectl does not interpret",) if extras is None else extras
    )
    files = found.listing(
        directory,
        POOL_FILE,
        f"{directory} holds {{count}} entries that PHP-FPM would not load as pool files. "
        "They were skipped.",
    )
    if directory in found.unlisted:
        reads.unread[version] = found.unlisted[directory]
    for file in files:
        _observe_pool_file(found, version, directory, file, reads)


def _collect_php_pools(shell: RemoteShell, php_fpm: WebStackComponentObservation) -> FpmPools:
    found = _Pools(shell, _POOLS_EXPLANATIONS, MAX_POOLS, _POOL_CAP)
    reads = _PoolReads()
    observation = _observe_installed(
        php_fpm.package, lambda packages: _observe_pools(found, packages, reads)
    )
    gap = ObservationOutcome.UNSUPPORTED if reads.incomplete else found.gap(observation.outcome)
    # Without an installed PHP-FPM package, no pool is missing.
    return FpmPools(
        observation,
        reads.unread,
        None if gap == ObservationOutcome.ABSENT else gap,
        reads.main_extras,
        reads.users,
    )


def _observe_pools(
    found: _Pools, packages: tuple[Package, ...], reads: _PoolReads
) -> Observation[tuple[PoolEntryObservation, ...]]:
    versions = [
        match.group(1) for package in packages if (match := PHP_FPM_PACKAGE.fullmatch(package.name))
    ]
    versions.sort(key=lambda version: [int(part) for part in version.split(".")])
    if not versions:
        return Observation(
            ObservationOutcome.UNSUPPORTED,
            (PACKAGE_QUERY,),
            "The dpkg database lists no PHP-FPM package for a specific PHP version, so "
            "Barectl cannot locate its pool directory.",
            (),
        )
    if len(versions) > MAX_VERSIONS:
        found.warn(
            f"More PHP-FPM versions are installed than Barectl reads. Only the first "
            f"{MAX_VERSIONS} were inspected."
        )
        versions = versions[:MAX_VERSIONS]
        reads.incomplete = True
    for version in found.each(versions):
        _collect_pools_of_version(found, version, reads)
    return found.observation()


def _observe_pool_file(
    found: _Pools, version: str, directory: str, file: str, reads: _PoolReads
) -> None:
    path = f"{directory}/{file}"
    text = found.read(path)
    if isinstance(text, _Failed):
        found.fail(text)
        return
    parsed = parse_pool_file(text)
    if parsed is None:
        found.fail(
            _Failed(
                ObservationOutcome.UNSUPPORTED,
                f"{path} does not define a supported PHP-FPM pool configuration. Only "
                "pool names and listen addresses are read.",
                path,
            )
        )
        return
    sections = parse_pool_sections(text)
    if parsed.includes or sections is None:
        # Included pools, or a pool whose user Barectl cannot tell, may share a site's socket
        # or identity.
        reads.incomplete = True
    for section in sections or ():
        reads.users[(version, section.name)] = dict(section.settings).get("user", "")
    if parsed.includes:
        found.warn(
            f"{path} includes other configuration files. Barectl does not read them, so "
            "pools they declare are not shown."
        )
    for name, listen in parsed.pools:
        _add_pool(
            found,
            PoolEntryObservation(
                version,
                name,
                ObservationOutcome.OBSERVED if listen else ObservationOutcome.UNSUPPORTED,
                listen,
                path,
                "" if listen else f"Pool {name} in {path} does not name a listen address.",
            ),
            directory,
        )
