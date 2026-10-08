"""Passive WordPress application evidence (docs/wordpress.md#passive-application-discovery).

Bounded native metadata, one fixed script that parses the private configuration as data on
the managed server, and fixed read-only catalog queries. Nothing here runs WP-CLI or
application PHP, escalates the SSH user's access, transfers a raw secret, or falls back to
an earlier snapshot. Application evidence is independent of the site's infrastructure state.
"""

import re
from dataclasses import dataclass, field, replace

from wordpress import convention as wp

from ..models import (
    ApplicationState,
    ConfigurationState,
    CoreQualification,
    DatabaseEngine,
    FileType,
    LoaderState,
    ObservationOutcome,
    SchemaState,
    SiteRouting,
    WebStackComponent,
)
from ..snapshot import (
    Observation,
    ObservedApplication,
    ObservedDatabase,
    ObservedSite,
    WebStackComponentObservation,
)
from ..ssh import RemoteShell
from .databases import MARIADB_UNIT, _is_root, _unread
from .probes import _Failed, _list_directory, _run
from .sites import WEB_ROOT, WEB_USER, _Node, _stat_paths

OBSERVED = ObservationOutcome.OBSERVED
INACCESSIBLE = ObservationOutcome.INACCESSIBLE
SOURCE_FILES = "WordPress files below the site's public and private directories"
SOURCE_SCRIPT = (
    "A fixed script on the server that parses the private configuration as data and prints "
    "only fixed tokens and its digest"
)
SOURCE_CATALOG = (
    "MariaDB information_schema table and column names of the site database, and the "
    "siteurl and home options"
)
NOT_ROOT = (
    "The SSH user is not root. The private configuration and the database catalog are "
    "readable only by root or the site user, and ordinary discovery never escalates."
)


@dataclass
class _Facts:
    """What one site's reads established; ``limits`` lists what they could not."""

    top_level: set[str] = field(default_factory=set)
    version: str = "none"
    loader: LoaderState = LoaderState.NOT_READ
    configuration: ConfigurationState = ConfigurationState.NOT_READ
    # The private configuration exists; its grammar is read only by the server-side script.
    configuration_listed: bool = False
    digest: str = ""
    schema: SchemaState = SchemaState.NOT_READ
    tables: int = 0
    site_url: str = ""
    home_url: str = ""
    options_read: bool = False
    blocked: list[str] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)


def collect_applications(
    shell: RemoteShell,
    components: tuple[WebStackComponentObservation, ...],
    sites: Observation[tuple[ObservedSite, ...]],
) -> Observation[tuple[ObservedSite, ...]]:
    """The sites, each with its passive WordPress application evidence."""
    bound = tuple(site for site in sites.value if site.identifier)
    if not bound:
        return sites
    root = _is_root(shell)
    by_component = {observed.component: observed for observed in components}
    catalog = _Catalog.read(shell, by_component[WebStackComponent.MARIADB], bound, root)
    return replace(
        sites,
        value=tuple(
            replace(site, application=_observe(shell, site, root, catalog))
            if site.identifier
            else site
            for site in sites.value
        ),
    )


@dataclass(frozen=True)
class _Catalog:
    """The schema summary of every MariaDB site database, or why it was not read."""

    schemas: dict[str, wp.Schema]
    failure: str = ""

    @classmethod
    def read(
        cls,
        shell: RemoteShell,
        mariadb: WebStackComponentObservation,
        sites: tuple[ObservedSite, ...],
        root: _Failed | bool,
    ) -> _Catalog:
        databases = tuple(
            f"s{site.identifier}" for site in sites if _has_mariadb_database(site.database)
        )
        if not databases:
            return cls({})
        unread = _unread(DatabaseEngine.MARIADB, mariadb, MARIADB_UNIT, root)
        if unread is not None:
            return cls({}, unread.warning or NOT_ROOT)
        output = _run(
            shell,
            wp.schema_command(databases),
            failed="root could not read the MariaDB catalog through its socket without a "
            "password, as the distribution's administration allows.",
        )
        if isinstance(output, _Failed):
            return cls({}, output.warning)
        try:
            return cls(dict(wp.parse_schema(output, databases)))
        except wp.CatalogFormatError:
            return cls({}, "The MariaDB catalog did not answer in a supported format.")


def _has_mariadb_database(database: ObservedDatabase | None) -> bool:
    return (
        database is not None
        and database.outcome == OBSERVED
        and database.engine == DatabaseEngine.MARIADB
        and bool(database.database)
    )


def _observe(
    shell: RemoteShell, site: ObservedSite, root: _Failed | bool, catalog: _Catalog
) -> ObservedApplication:
    facts = _Facts()
    identifier = site.identifier
    _read_directories(shell, facts, site)
    privileged = root is True
    if not privileged:
        facts.limits.append(root.warning if isinstance(root, _Failed) else NOT_ROOT)
    elif not facts.limits and _worth_reading(facts, site):
        _read_files(shell, facts, identifier)
    _read_schema(shell, facts, site, catalog, privileged=privileged)
    return _classify(site, facts)


def _worth_reading(facts: _Facts, site: ObservedSite) -> bool:
    return (
        bool(facts.top_level)
        or facts.configuration_listed
        or site.routing in {SiteRouting.WORDPRESS, SiteRouting.WORDPRESS_GATE}
    )


_ENTRIES = frozenset(
    {"index.php", "wp-load.php", "wp-settings.php", "wp-admin", "wp-includes", "wp-content"}
)


def _read_directories(shell: RemoteShell, facts: _Facts, site: ObservedSite) -> None:
    identifier = site.identifier
    public, private = wp.public_root(identifier), f"{WEB_ROOT}/{identifier}/private"
    facts.source.append(SOURCE_FILES)
    listing = _list_directory(shell, public, hidden=True)
    if isinstance(listing, _Failed):
        if listing.missing:
            facts.loader = LoaderState.ABSENT
        else:
            facts.limits.append(listing.warning)
    else:
        facts.top_level = set(listing) & (_ENTRIES | {LOADER})
        if LOADER not in listing:
            facts.loader = LoaderState.ABSENT
    private_listing = _list_directory(shell, private, hidden=True)
    if isinstance(private_listing, _Failed):
        if private_listing.missing:
            facts.configuration = ConfigurationState.ABSENT
        else:
            facts.limits.append(private_listing.warning)
    elif LOADER in private_listing:
        facts.configuration_listed = True
    else:
        facts.configuration = ConfigurationState.ABSENT
    _check_metadata(shell, facts, site, public, private)


LOADER = "wp-config.php"


def _check_metadata(
    shell: RemoteShell, facts: _Facts, site: ObservedSite, public: str, private: str
) -> None:
    user = f"s{site.identifier}"
    expectations = []
    if LOADER in facts.top_level:
        expectations.append((f"{public}/{LOADER}", user, WEB_USER, 0o640))
    if facts.configuration_listed:
        expectations.append((f"{private}/{LOADER}", user, user, 0o600))
    if not expectations:
        return
    nodes = _stat_paths(shell, tuple(path for path, *_ in expectations))
    for path, owner, group, mode in expectations:
        node = nodes[path]
        if isinstance(node, _Failed):
            facts.limits.append(node.warning)
        elif not _expected(node, owner, group, mode):
            facts.blocked.append(
                f"{path} must be a regular file owned by {owner}:{group} with mode {mode:04o} "
                "and one link."
            )


def _expected(node: _Node, owner: str, group: str, mode: int) -> bool:
    return node.file_type == FileType.FILE and (node.owner, node.group, node.mode, node.links) == (
        owner,
        group,
        mode,
        1,
    )


def _read_files(shell: RemoteShell, facts: _Facts, identifier: str) -> None:
    facts.source.append(SOURCE_SCRIPT)
    output = _run(
        shell,
        wp.inspection_command(identifier),
        failed="The fixed WordPress file inspection failed on the server.",
        missing="The server has no python3, so Barectl cannot parse the WordPress "
        "configuration on the server.",
    )
    if isinstance(output, _Failed):
        facts.limits.append(output.warning)
        return
    inspected = wp.parse_inspection(output)
    if inspected is None:
        facts.limits.append("The WordPress file inspection did not answer in a supported format.")
        return
    facts.version = inspected.version
    _loader(facts, inspected.loader)
    _configuration(facts, inspected)


def _loader(facts: _Facts, state: str) -> None:
    match state:
        case "exact":
            facts.loader = LoaderState.EXACT
        case "absent":
            facts.loader = LoaderState.ABSENT
        case "other":
            facts.loader = LoaderState.OTHER
            facts.blocked.append("The public wp-config.php is not the fixed loader.")
        case _:
            facts.limits.append("The public wp-config.php could not be read.")


def _configuration(facts: _Facts, inspected: wp.FileInspection) -> None:
    match inspected.configuration:
        case "supported":
            facts.configuration = ConfigurationState.SUPPORTED
            facts.digest = inspected.configuration_digest
        case "absent":
            facts.configuration = ConfigurationState.ABSENT
        case "unsupported":
            facts.configuration = ConfigurationState.UNSUPPORTED
            facts.blocked.append(
                "The private configuration is not the supported grammar"
                + (f"; the first refused line is {inspected.line}." if inspected.line else ".")
            )
        case "other":
            facts.configuration = ConfigurationState.UNSUPPORTED
            facts.blocked.append("The private configuration is not a plain regular file.")
        case _:
            facts.limits.append("The private configuration could not be read.")


def _read_schema(
    shell: RemoteShell,
    facts: _Facts,
    site: ObservedSite,
    catalog: _Catalog,
    *,
    privileged: bool,
) -> None:
    database = site.database
    if database is None:
        facts.limits.append("The site's database binding was not observed.")
        return
    if database.outcome == ObservationOutcome.ABSENT or (
        database.outcome == OBSERVED and not database.database
    ):
        facts.schema = SchemaState.ABSENT
        return
    if database.outcome == OBSERVED and database.engine != DatabaseEngine.MARIADB:
        return
    if not privileged:
        return
    if database.outcome != OBSERVED:
        facts.limits.append(database.warning or "The site's database binding was not readable.")
        return
    name = f"s{site.identifier}"
    schema = catalog.schemas.get(name)
    if schema is None:
        facts.limits.append(catalog.failure or "The site database was not in the catalog read.")
        return
    facts.source.append(SOURCE_CATALOG)
    _summarize(shell, facts, name, schema)


def _summarize(shell: RemoteShell, facts: _Facts, name: str, schema: wp.Schema) -> None:
    facts.tables = schema.tables
    if schema.ambiguous:
        facts.schema = SchemaState.ALTERED
        facts.blocked.append(
            "Another table prefix in the site database holds its own users and options tables, "
            "so the WordPress prefix is ambiguous."
        )
    elif schema.complete:
        facts.schema = SchemaState.COMPLETE
        _read_options(shell, facts, name)
    elif facts.tables == len(wp.CORE_TABLES):
        facts.schema = SchemaState.ALTERED
        facts.blocked.append("A core table lacks a required column.")
    else:
        facts.schema = SchemaState.PARTIAL if facts.tables else SchemaState.ABSENT


def _read_options(shell: RemoteShell, facts: _Facts, name: str) -> None:
    output = _run(
        shell, wp.options_command(name), failed="The canonical options were not readable."
    )
    if isinstance(output, _Failed):
        facts.limits.append(output.warning)
        return
    try:
        options = wp.parse_options(output)
    except wp.CatalogFormatError:
        facts.limits.append("The canonical options did not answer in a supported format.")
        return
    facts.options_read = True
    facts.site_url = options.get("siteurl", "")
    facts.home_url = options.get("home", "")


_NO_FILE = frozenset({"none", "denied", "other"})
_NO_VERSION = _NO_FILE | {"unparseable"}
_CANONICAL_URL = re.compile(r"https://([a-z0-9.-]{1,46})")


def _canonical_problem(site: ObservedSite, facts: _Facts) -> str:
    urls = (facts.site_url, facts.home_url)
    if not all(urls) or facts.site_url != facts.home_url:
        return "The siteurl and home options are missing or differ."
    found = _CANONICAL_URL.fullmatch(facts.site_url)
    if found is None or found[1] not in site.server_names:
        return "The siteurl and home options are not the HTTPS root of a name of the site."
    if site.canonical_name and found[1] != site.canonical_name:
        return "The siteurl and home options are not the canonical name of the site file."
    return ""


def _classify(site: ObservedSite, facts: _Facts) -> ObservedApplication:
    markers = len(facts.top_level & _ENTRIES) + (1 if facts.version not in _NO_FILE else 0)
    wordpress_routed = site.routing in {SiteRouting.WORDPRESS, SiteRouting.WORDPRESS_GATE}
    version = facts.version if facts.version not in _NO_VERSION else ""
    qualification = wp.qualification(version) if version else CoreQualification.NOT_OBSERVED
    database = site.database
    if (
        database is not None
        and database.outcome == OBSERVED
        and database.engine == DatabaseEngine.POSTGRESQL
        and (markers or wordpress_routed)
    ):
        facts.blocked.append(
            "The site's database binding is PostgreSQL; WordPress requires the MariaDB binding."
        )
    if facts.options_read and not facts.blocked:
        problem = _canonical_problem(site, facts)
        if problem:
            facts.blocked.append(problem)
    complete = (
        markers == len(wp.MARKERS)
        and facts.loader is LoaderState.EXACT
        and facts.configuration is ConfigurationState.SUPPORTED
        and facts.schema is SchemaState.COMPLETE
        and database is not None
        and database.conforms
        and database.engine == DatabaseEngine.MARIADB
    )
    if facts.blocked:
        state = ApplicationState.BLOCKED
    elif facts.limits:
        state = ApplicationState.UNREADABLE
    elif complete:
        state = ApplicationState.INSTALLED
    elif (
        not markers
        and not wordpress_routed
        and facts.loader in {LoaderState.ABSENT, LoaderState.NOT_READ}
        and facts.configuration in {ConfigurationState.ABSENT, ConfigurationState.NOT_READ}
        and not facts.tables
    ):
        state = ApplicationState.ABSENT
    elif (
        not wordpress_routed
        and facts.loader is LoaderState.ABSENT
        and facts.configuration is ConfigurationState.ABSENT
        and not facts.tables
    ):
        state = ApplicationState.CANDIDATE
    else:
        state = ApplicationState.PARTIAL
    return ObservedApplication(
        state=state,
        core_version=version,
        qualification=qualification,
        loader=facts.loader,
        configuration=facts.configuration,
        configuration_digest=facts.digest,
        markers_present=markers,
        markers_total=len(wp.MARKERS),
        schema=facts.schema,
        tables_present=facts.tables,
        site_url=facts.site_url,
        home_url=facts.home_url,
        blocked=tuple(dict.fromkeys(facts.blocked)),
        limits=tuple(dict.fromkeys(facts.limits)),
        source=tuple(dict.fromkeys(facts.source)),
        warning=_warning(qualification, version, facts, database),
    )


def _warning(
    qualification: CoreQualification,
    version: str,
    facts: _Facts,
    database: ObservedDatabase | None,
) -> str:
    notes = []
    if qualification is CoreQualification.NEWER:
        notes.append(
            f"WordPress {version} is newer than the qualified {wp.CORE_VERSION}. "
            "Barectl reports it and does not downgrade it."
        )
    elif qualification is CoreQualification.OLDER:
        notes.append(f"WordPress {version} is older than the qualified {wp.CORE_VERSION}.")
    elif qualification is CoreQualification.UNRECOGNIZED:
        notes.append(f"The version literal {version} is not a WordPress release version.")
    if (
        database is not None
        and database.outcome == OBSERVED
        and not database.conforms
        and facts.schema is SchemaState.COMPLETE
    ):
        notes.append(
            "The site's database binding is not confirmed as the convention requires. "
            + database.warning
        )
    return " ".join(notes)
