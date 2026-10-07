"""Binding admission: a complete site, an established engine and driver, and the catalog's
state under the site's name (docs/databases.md#database-bindings)."""

import secrets
from dataclasses import dataclass

from bootstrap import inspection as bootstrap_inspection
from bootstrap import native as bootstrap_native
from bootstrap import profiles
from bootstrap.apply import current_units
from bootstrap.evidence import parse_package_states
from bootstrap.inspection import Reader
from bootstrap.models import PlanEffect, PlanEvidence, PlanRefusal, Privilege
from bootstrap.review import Draft, EvidenceDraft, check_platform
from bootstrap.review import review as bootstrap_review
from discovery.models import DatabaseEngine
from discovery.observations.databases import (
    Binding,
    BindingState,
    CatalogFormatError,
    Step,
)
from discovery.ssh import RemoteShell
from sites import admission as site_admission
from sites import inspection as site_inspection
from sites.native import script

from . import binding, drivers, native

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
Kind = PlanEvidence.Kind
_LISTED = 3
UNIT = f"{bootstrap_native.UNIT_PREFIX}{'0' * 32}.service"


@dataclass
class BindingDraft(Draft):
    identifier: str = ""
    engine: DatabaseEngine = DatabaseEngine.MARIADB
    token: str = ""
    uid: int = 0
    gid: int = 0
    engine_version: str = ""
    driver_version: str = ""
    other_engine: bool = False
    # PostgreSQL: template1's libc locale, which the database is created with.
    locale: str = ""
    statements: tuple[binding.Statement, ...] = ()
    payload_bytes: int | None = None

    @property
    def principal(self) -> str:
        return binding.principal(self.identifier)


def intent(identifier: str, engine: DatabaseEngine) -> str:
    return (
        f"Create the {engine.label} database and principal s{identifier} for the site "
        f"{identifier}, authenticated by its Linux user."
    )


def finish_intent(identifier: str, engine: DatabaseEngine) -> str:
    return (
        f"Finish the {engine.label} database and principal s{identifier} for the site "
        f"{identifier}, running only the statements a partly applied run left missing."
    )


def prepare(shell: RemoteShell, identifier: str, engine: DatabaseEngine) -> BindingDraft:
    spec = binding.ENGINES[engine]
    token = secrets.token_hex(16)
    site = site_inspection.inspect(shell, identifier, token)
    draft = BindingDraft(
        spec.action,
        intent(identifier, engine),
        site.platform,
        site.release,
        identifier=identifier,
        engine=engine,
        token=token,
    )
    check_platform(draft, site.platform)
    for gap in site.gaps:
        draft.refuse(Reason.INCOMPLETE, gap)
    if site.release is None or site.platform is None:
        return draft
    if not site.read_privilege:
        draft.refuse(
            Reason.PRIVILEGE,
            "The SSH user is not root, and sudo -n -l does not authorize Barectl's fixed "
            "read-only inspection commands without a password. Binding preparation reads the "
            "site, the engine's catalog and its administration as root; the permission to "
            "prepare database plans is the explicit authority for that privileged read. "
            "Barectl never installs a sudo policy or asks for a password.",
        )
        return draft
    _Admission(draft, shell, site).run()
    return draft


@dataclass
class _Admission:
    draft: BindingDraft
    shell: RemoteShell
    site: site_inspection.SiteEvidence

    @property
    def spec(self) -> binding.EngineSpec:
        return binding.ENGINES[self.draft.engine]

    def run(self) -> None:
        self._site()
        self._engine()
        self._driver()
        before = self._catalog()
        self._probe_path()
        if before is None or not self.draft.eligible:
            return
        if self.draft.no_changes:
            return
        self._changes(before)

    def _site(self) -> None:
        draft, site = self.draft, self.site
        identifier = draft.identifier
        found = site_admission.recognize_trees(site)
        recognized = found.sites.get(identifier) if found else None
        if recognized is None:
            draft.refuse(
                Reason.PREREQUISITE,
                f"There is no site {identifier} following the site convention. Create it with "
                "a site plan first; a database is bound only to a complete site.",
            )
            return
        reviewed = site_admission.review(
            identifier, recognized.names, draft.token, site, certificates_expected=True
        )
        if not reviewed.no_changes:
            problems = "; ".join(text for _, text in reviewed.refusals[:_LISTED])
            draft.refuse(
                Reason.PREREQUISITE,
                f"The site {identifier} is not complete as the site convention requires, so "
                f"no database is bound to it: {problems or 'its review proposes changes'}",
            )
            return
        draft.evidence += [
            item for item in reviewed.evidence if item.kind == Kind.SITE_REVALIDATION
        ]
        fields = (site.accounts.user if site.accounts else "").split(":")
        draft.uid, draft.gid = int(fields[2]), int(fields[3])

    def _engine(self) -> None:
        draft, spec = self.draft, self.spec
        evidence = bootstrap_inspection.inspect(self.shell, spec.profile)
        reviewed = bootstrap_review(spec.profile, evidence, current_units())
        if not reviewed.no_changes:
            problems = "; ".join(text for _, text in reviewed.refusals[:_LISTED])
            draft.refuse(
                Reason.PREREQUISITE,
                f"{draft.engine.label} is not established as its bootstrap profile requires. "
                f"Prepare and apply the {spec.profile.label} first"
                f"{f': {problems}' if problems else '.'}",
            )
            return
        draft.engine_version = reviewed.roots[0].version if reviewed.roots else ""
        draft.evidence += [
            item for item in reviewed.evidence if item.kind == Kind.PACKAGE_REVALIDATION
        ]
        if reviewed.release is not None:
            other = binding.ENGINE_PROFILES[binding.other_engine(draft.engine)]
            draft.other_engine = self._installed(profiles.profile(reviewed.release, other).roots[0])

    def _installed(self, package: str) -> bool:
        reader = Reader(self.shell)
        states = reader.parse(
            reader.read(
                bootstrap_inspection.package_states([package]),
                f"dpkg's state of {package}",
                ok=(0, 1),
            ),
            parse_package_states,
        )
        for gap in reader.gaps:
            self.draft.refuse(Reason.INCOMPLETE, gap)
        return any(state.installed for state in states or ())

    def _driver(self) -> None:
        draft, spec = self.draft, self.spec
        reviewed = drivers.prepare(self.shell, spec.driver)
        if not reviewed.no_changes:
            draft.refuse(
                Reason.PREREQUISITE,
                f"The {spec.driver.label} is not installed and enabled for PHP-FPM. Prepare and "
                f"apply the {spec.driver.label} plan first; a binding plan never installs it.",
            )
            return
        draft.driver_version = reviewed.roots[0].version if reviewed.roots else ""
        draft.fingerprint(
            Kind.DRIVER,
            [f"{root.name} {root.version}" for root in reviewed.roots],
            f"{reviewed.roots[0].name} {draft.driver_version}, installed and loaded by "
            "PHP-FPM, rechecked before applying."
            if reviewed.roots
            else "",
        )

    def _read(self, argv: list[str], what: str) -> str | None:
        reader = Reader(self.shell)
        root = self.site.platform is not None and self.site.platform.privilege == Privilege.ROOT
        if not root and self.shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
            self.draft.refuse(
                Reason.PRIVILEGE,
                f"sudo -n -l does not authorize Barectl's fixed read of {what}.",
            )
            return None
        text = reader.read(bootstrap_native.privileged(argv, root=root), what)
        for gap in reader.gaps:
            self.draft.refuse(Reason.INCOMPLETE, gap)
        return text

    def _catalog(self) -> str | None:
        """The catalog read's text, when it shows the binding absent or satisfied."""
        draft = self.draft
        if not draft.eligible:
            return None
        name = draft.principal
        function = binding.catalog_function(name, draft.engine, draft.other_engine)
        text = self._read(
            script(f"export LC_ALL=C PATH=/usr/sbin:/usr/bin; {function}; c"),
            f"the {draft.engine.label} catalog",
        )
        if text is None:
            return None
        try:
            read = binding.recognize(text, draft.engine, name)
        except CatalogFormatError, ValueError:
            draft.refuse(
                Reason.INCOMPLETE,
                f"The {draft.engine.label} catalog did not answer in a supported format.",
            )
            return None
        state = read.binding
        if read.other and read.other.strip():
            draft.refuse(
                Reason.EXISTING_BINDING,
                f"{binding.other_engine(draft.engine).label} already holds a principal, "
                f"database or grant named {name}. A site has at most one database binding, and "
                "Barectl never switches it to another engine.",
            )
            return None
        if draft.engine == DatabaseEngine.POSTGRESQL and not self._locale(read.template):
            return None
        if state.exposures:
            draft.refuse(
                Reason.NOT_FOLLOWING,
                f"Database resources named {name} do not follow the database convention. "
                "Restore the convention through ordinary administration, then prepare again.",
            )
            return None
        draft.fingerprint(
            Kind.CATALOG,
            [text],
            f"The {draft.engine.label} rows under {name}: {state.state.value}.",
        )
        return self._state(state, text)

    def _locale(self, template: tuple[str, ...]) -> bool:
        """docs/site-conventions.md#database-convention: template1's libc locale."""
        draft = self.draft
        draft.locale = binding.reviewed_locale(template)
        if not draft.locale:
            encoding, provider, collate, ctype = template
            draft.refuse(
                Reason.CUSTOMIZED,
                f"template1 uses {encoding} with locale provider {provider}, collation "
                f"{collate} and character type {ctype}. The database convention creates a site "
                "database from template0 with template1's libc UTF-8 locale only when it is one "
                "of C.UTF-8, C.utf8, en_US.UTF-8 or en_US.utf8.",
            )
        return bool(draft.locale)

    def _state(self, found: Binding, text: str) -> str | None:
        draft = self.draft
        match found.state:
            case BindingState.ABSENT:
                return text
            case BindingState.SATISFIED:
                draft.effects.append(
                    (
                        Effect.NO_CHANGES,
                        (
                            f"No changes. {draft.principal} already exists exactly as the database "
                            "convention creates it, so the binding is complete."
                        ),
                    )
                )
                return text
            case BindingState.PARTIAL:
                completed = set(found.completed)
                draft.intent = finish_intent(draft.identifier, draft.engine)
                draft.statements = tuple(
                    statement
                    for statement in binding.statements(draft.engine, draft.principal, draft.locale)
                    if statement.step not in completed
                )
                return text
            case _:
                draft.refuse(
                    Reason.NOT_FOLLOWING,
                    f"Database resources named {draft.principal} do not follow the database "
                    "convention. Restore the convention through ordinary administration, "
                    "then prepare again.",
                )
        return None

    def _probe_path(self) -> None:
        draft = self.draft
        path = binding.probe_path(draft.identifier, draft.token)
        text = self._read(
            script(f"if [ -e {path} ] || [ -L {path} ]; then echo present; else echo absent; fi"),
            "the probe's path",
        )
        if text is not None and text.strip() != "absent":
            draft.refuse(Reason.COLLISION, f"{path} exists. Remove it, then prepare again.")

    def _changes(self, before: str) -> None:
        draft = self.draft
        name = draft.principal
        after = binding.predicted_after(before, draft.engine, name, draft.locale)
        draft.evidence += [
            EvidenceDraft(
                Kind.CATALOG_REVALIDATION,
                binding.digest(before),
                f"The catalog rows under {name}, rechecked under the lock and again "
                "immediately before the first statement.",
            ),
            EvidenceDraft(
                Kind.CATALOG_AFTER,
                binding.digest(after),
                f"The catalog rows under {name} once every statement took effect, compared "
                "after the last one.",
            ),
        ]
        draft.statements = draft.statements or binding.statements(draft.engine, name, draft.locale)
        _effects(draft)
        self._payload(before, after)

    def _payload(self, before: str, after: str) -> None:
        draft = self.draft
        digests = {item.kind: item.fingerprint for item in draft.evidence}
        try:
            text = native.binding_payload(
                UNIT,
                "00000000-0000-0000-0000-000000000000",
                0,
                change(draft, digests, before=binding.digest(before), after=binding.digest(after)),
            )
        except ValueError, KeyError:
            draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed payload.")
            return
        draft.payload_bytes = len(text.encode())
        if draft.payload_bytes > bootstrap_native.MAX_PAYLOAD:
            draft.refuse(
                Reason.PAYLOAD_TOO_LARGE,
                f"The binding's payload is {draft.payload_bytes} bytes, more than Barectl "
                "submits in one run. Barectl never splits a reviewed action.",
            )


def change(
    draft: BindingDraft, digests: dict[PlanEvidence.Kind, str], *, before: str, after: str
) -> native.BindingChange:
    release = draft.release.version if draft.release else ""
    return native.BindingChange(
        release=release,
        identifier=draft.identifier,
        engine=draft.engine,
        uid=draft.uid,
        gid=draft.gid,
        token=draft.token,
        probe=binding.render_probe(draft.engine, draft.principal, draft.token),
        site_digest=digests[Kind.SITE_REVALIDATION],
        engine_digest=digests[Kind.PACKAGE_REVALIDATION],
        driver_version=draft.driver_version,
        catalog_before=before,
        catalog_after=after,
        other=draft.other_engine,
        locale=draft.locale,
        statements=draft.statements,
    )


def _effects(draft: BindingDraft) -> None:
    name, engine = draft.principal, draft.engine
    steps = {statement.step for statement in draft.statements}
    statements = "; ".join(statement.text for statement in draft.statements)
    probe = binding.probe_path(draft.identifier, draft.token)
    effects: list[tuple[Effect, str]] = []
    if Step.PRINCIPAL in steps:
        effects.append(
            (
                Effect.DATABASE_PRINCIPAL,
                (
                    f"Creates the {engine.label} principal {name}, which authenticates only as the "
                    f"Linux user {name} through the local socket, with no password and no other "
                    "host."
                ),
            )
        )
    if Step.DATABASE in steps:
        effects.append(
            (
                Effect.DATABASE_CREATION,
                f"Creates the database {name} with {binding.encoding_text(engine, draft.locale)}.",
            )
        )
    if steps & {Step.PRIVILEGES, Step.SCHEMA}:
        effects.append((Effect.DATABASE_PRIVILEGES, binding.privileges_text(engine, name)))
    effects += [
        (
            Effect.SITE_FILES,
            (
                f"Each statement runs in its own client invocation, in this order: {statements}. "
                "No statement is conditional, replaced or dropped; the effects an earlier run "
                "already made are revalidated as exact and never redone."
            ),
        ),
        (
            Effect.ACCEPTANCE_PROBE,
            (
                f"Before the first statement, the site's pool runs the temporary probe {probe}, "
                f"root's and readable by {name}, to show that it runs as {name} with the driver "
                "loaded; after the last, it connects as the site, creates, uses and drops a table, "
                "and is refused other databases, administration and a password-less TCP login. "
                "The probe is then removed."
            ),
        ),
        (
            Effect.CONNECTION,
            binding.connection_text(engine, draft.identifier),
        ),
        (
            Effect.NO_ROLLBACK,
            (
                "Barectl never drops what it created. A failure after the first statement leaves "
                "the principal and anything created after it; ordinary administration completes or "
                "removes them."
            ),
        ),
    ]
    draft.effects += effects
    draft.postconditions += [
        f"The {engine.label} catalog holds exactly the convention's rows under {name}.",
        (
            f"The administrator's authentication, listeners and services are unchanged, and "
            f"{probe} does not exist."
        ),
    ]
