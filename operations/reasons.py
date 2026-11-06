"""The one result-reason vocabulary for every change body (#495).

A body's composer declares the reasons its staged text can print, next to that text. A
kind's vocabulary is the union of the fragments it stages plus the engine's admission
prelude, which is declared once here for every kind. ``register_kind`` merges those
declarations, indexes every sentence by reason and execution outcome, and refuses a
duplicate reason with conflicting wording.

Reading stays permissive by construction: the accepted set is every registered kind's
reasons plus the retired set, so another controller can read a line printed by a body it did
not stage and an older refusal never becomes unreadable evidence
(docs/adr/0035-one-change-engine-with-effect-derived-consent.md).
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import native
from .models import Result

REPOSITORY: Final = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ResultReason:
    """One fixed wire reason and one plain sentence per outcome it is paired with.

    Most reasons carry one sentence. The case that proves the shape is a lock reason that
    reads as a refusal before changes in one outcome and as contention in another.
    """

    name: str
    sentences: Mapping[Result, str]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.name):
            raise ValueError(f"Not a result reason name: {self.name!r}")
        if not self.sentences:
            raise ValueError(f"Result reason {self.name!r} declares no sentence.")
        for outcome, sentence in self.sentences.items():
            if not isinstance(outcome, Result):
                raise ValueError(f"Result reason {self.name!r} names an unknown outcome.")
            if not sentence.strip():
                raise ValueError(
                    f"Result reason {self.name!r} has no sentence for {outcome.value!r}."
                )

    @property
    def outcomes(self) -> frozenset[Result]:
        return frozenset(self.sentences)

    def sentence(self, outcome: Result) -> str:
        return self.sentences.get(outcome, "")


def _before_and_partial(sentence: str) -> Mapping[Result, str]:
    """The two outcomes a body prints before it succeeds: refused and partly applied."""
    return {Result.REFUSED: sentence, Result.PARTIAL: sentence}


# The generic sentence for an outcome whose reason has no sentence of its own.
OUTCOME_SENTENCES: Final[dict[Result, str]] = {
    Result.REFUSED: "The run stopped before changing anything.",
    Result.LOCK_BUSY: (
        "Another change held Barectl's mutation lock on the server, so the run stopped "
        "before changing anything. Prepare a new review after that change finishes."
    ),
    Result.PARTIAL: (
        "The run stopped after changing the server, so the change is partly applied and "
        "no rollback happens. Read the unit's journal on the server, then prepare a new "
        "review of what remains."
    ),
    Result.FAILED: (
        "The run failed without reporting how far it got, so what changed is unknown and "
        "no rollback happens. Read the unit's journal on the server, then prepare a new "
        "review before any later change."
    ),
    Result.TIMED_OUT: (
        f"The run reached its {native.RUNTIME_MAX} limit and systemd stopped it; what "
        "changed is unknown and no rollback happens. Read the unit's journal on the "
        "server, then prepare a new review."
    ),
}

# The engine's own admission prelude, declared once for every kind.
ADMISSION: Final = (
    ResultReason(
        "unsafe_lock",
        _before_and_partial(
            "The lock directory /run/lock/barectl or its lock file is not a root-owned private "
            "directory with an empty lock file, so the run stopped before changing anything. "
            "Remove it through ordinary administration, then prepare again."
        ),
    ),
    ResultReason(
        "boot",
        _before_and_partial(
            "The server restarted after the change was reviewed, so the run stopped before "
            "changing anything. Prepare a new review."
        ),
    ),
    ResultReason(
        "deadline",
        _before_and_partial(
            "The review's admission deadline had passed on the server's clock when the run "
            "started, so it stopped before changing anything. Prepare a new review."
        ),
    ),
    ResultReason(
        "active_run",
        _before_and_partial(
            "Another barectl run still had processes on the server, so this run stopped before "
            "changing anything. Prepare a new review after it finishes."
        ),
    ),
    ResultReason(
        "revert_active",
        _before_and_partial(
            "A firewall or sign-in change is inside its confirmation window, or its put-back "
            "has not finished. The server keeps the change it can restore on its own, so this "
            "run stopped before changing anything. Wait for the window to close, then prepare "
            "again."
        ),
    ),
    ResultReason(
        "capacity",
        _before_and_partial(
            "The server kept too many finished barectl runs when this run held the lock, so it "
            "stopped before changing anything. Clear finished runs with a reviewed cleanup, "
            "then prepare again."
        ),
    ),
    ResultReason(
        "affected_sites",
        _before_and_partial(
            "Affected sites changed, review again: the sites this shared change reaches differ "
            "from the reviewed list, so the run stopped before changing anything."
        ),
    ),
    ResultReason(
        "apt_active",
        _before_and_partial(
            "Package maintenance still has processes. Wait for it to finish and review again."
        ),
    ),
    ResultReason(
        "apt_unreadable",
        _before_and_partial("Package maintenance process state could not be read. Review again."),
    ),
    ResultReason(
        "evidence",
        _before_and_partial(
            "The reviewed evidence changed on the server, so the run stopped before changing "
            "anything. Prepare a new review."
        ),
    ),
    ResultReason(
        "active_backup",
        _before_and_partial(
            "This site's scheduled backup still had processes on the server, so this run "
            "stopped before changing anything. Prepare a new review after it finishes."
        ),
    ),
)

# Reasons no current body prints. A server that still holds an old run reads its last
# sentence; no registered composer may produce one again.
RETIRED_REASONS: Final = (
    ResultReason(
        "backup_offsite",
        _before_and_partial(
            "The offsite copy could not be completed, so the recovery point saved on this "
            "server is unchanged. Copy it offsite again when the storage is reachable."
        ),
    ),
    ResultReason(
        "laravel_platform",
        _before_and_partial(
            "The release requires a PHP version or extension the site's runtime does not "
            "provide, so the run stopped before switching code. The previous release is still "
            "serving."
        ),
    ),
    ResultReason(
        "site_remove_configuration",
        _before_and_partial(
            "The removal stopped after removing the site's services and before removing its "
            "configuration. Read the run's journal on the server, then prepare a new review of "
            "what remains."
        ),
    ),
    ResultReason(
        "site_remove_files",
        _before_and_partial(
            "The removal stopped after removing the site's database or certificate and while "
            "removing its files. Read the run's journal on the server, then prepare a new "
            "review of what remains."
        ),
    ),
    ResultReason(
        "site_remove_gate",
        _before_and_partial(
            "The removal stopped while pausing the site's serving, so nothing after that ran. "
            "Read the run's journal on the server, then prepare a new review."
        ),
    ),
    ResultReason(
        "site_remove_services",
        _before_and_partial(
            "The removal stopped after removing the site's Caddy route and while stopping its "
            "services. Read the run's journal on the server, then prepare a new review of what "
            "remains."
        ),
    ),
    ResultReason(
        "wordpress_archive",
        _before_and_partial(
            "The pinned WordPress archive could not be downloaded, so the run stopped before "
            "installing application files. Check the run's journal, then prepare a new review."
        ),
    ),
    ResultReason(
        "wordpress_archive_digest",
        _before_and_partial(
            "The downloaded WordPress archive did not match the pinned size or SHA-256, so it "
            "was discarded and nothing was installed. Check the server's network and prepare a "
            "new review."
        ),
    ),
    ResultReason(
        "wordpress_configuration",
        _before_and_partial(
            "The private WordPress configuration is missing or outside the supported grammar, "
            "so Barectl did not overwrite it. Correct it through ordinary administration, then "
            "prepare a new review."
        ),
    ),
    ResultReason(
        "wordpress_extract",
        _before_and_partial(
            "The pinned WordPress archive could not be extracted safely, so no application "
            "files were published. Check the run's journal, then prepare a new review."
        ),
    ),
    ResultReason(
        "wordpress_install",
        _before_and_partial(
            "WordPress did not complete its installation, so the maintenance gate is still up. "
            "Read the run's journal on the server, then prepare a new review."
        ),
    ),
    ResultReason(
        "wordpress_readiness",
        _before_and_partial(
            "The site did not answer its home, login and permalink pages over HTTPS, so "
            "Barectl restored the maintenance gate. Read the run's journal and prepare a new "
            "review."
        ),
    ),
    ResultReason(
        "wordpress_tables",
        _before_and_partial(
            "The site's WordPress tables already exist without a complete installation, so "
            "Barectl did not reinstall into them. Inspect the database through ordinary "
            "administration and prepare a new review."
        ),
    ),
)
RETIRED: Final = frozenset(reason.name for reason in RETIRED_REASONS)

_INDEX: Final[dict[tuple[str, Result], str]] = {}
_RETIRED_INDEX: Final[dict[tuple[str, Result], str]] = {}
_KIND_REASONS: Final[dict[str, tuple[ResultReason, ...]]] = {}
_BODY_VOCABULARIES: Final[dict[str, tuple[tuple[ResultReason, ...], tuple[str, ...]]]] = {}
_KIND_BY_SLUG: Final[dict[str, object]] = {}
_ACCEPTED: Final[set[str]] = {""} | RETIRED | {reason.name for reason in ADMISSION}


def _index(reason: ResultReason) -> None:
    for outcome, sentence in reason.sentences.items():
        key = (reason.name, outcome)
        declared = _INDEX.get(key)
        if declared is not None and declared != sentence:
            raise ValueError(
                "Two composers declare different wording for result reason "
                f"{reason.name!r} and outcome {outcome.value!r}."
            )
        _INDEX[key] = sentence


for _reason in (*ADMISSION, *RETIRED_REASONS):
    if _reason.name in RETIRED:
        for _outcome, _sentence in _reason.sentences.items():
            _RETIRED_INDEX[(_reason.name, _outcome)] = _sentence
    else:
        _index(_reason)


def register_kind(kind: object) -> None:
    """Merge one kind's body vocabulary with the admission prelude and index it."""
    declared = tuple(getattr(kind, "reasons", ()) or ())
    sources = tuple(getattr(kind, "body_sources", ()) or ())
    slug = str(getattr(kind, "slug", ""))
    if sources and not declared:
        raise ValueError(f"Change kind {slug!r} stages a body but declares no result reasons.")
    _KIND_REASONS[slug] = declared
    _KIND_BY_SLUG[slug] = kind
    for reason in declared:
        _index(reason)
    _ACCEPTED.update(reason.name for reason in declared)


def register_body(
    name: str,
    declared: tuple[ResultReason, ...],
    sources: tuple[str, ...] = (),
) -> None:
    """Register a non-kind composer's vocabulary, such as a scheduled integrity body."""
    _BODY_VOCABULARIES[name] = (tuple(declared), tuple(sources))
    for reason in declared:
        _index(reason)
    _ACCEPTED.update(reason.name for reason in declared)


def accepted(reason: str) -> bool:
    """Whether the parser recognizes ``reason`` as a result reason."""
    return reason in _ACCEPTED


def accepted_reasons() -> frozenset[str]:
    return frozenset(_ACCEPTED)


def sentence(outcome: Result, reason: str) -> str:
    """The one sentence for a reason and outcome; never keyed by kind."""
    specific = _INDEX.get((reason, outcome)) or _RETIRED_INDEX.get((reason, outcome))
    if specific:
        return specific
    return OUTCOME_SENTENCES.get(outcome, "")


# The manifest -------------------------------------------------------------------------------

_PAIR_CLASS_FIRST = re.compile(
    r'"class"\s*:\s*"([a-z_]+)"[^\n}]*?"reason"\s*:\s*"([a-z][a-z0-9_]*)"'
)
_PAIR_REASON_FIRST = re.compile(
    r'"reason"\s*:\s*"([a-z][a-z0-9_]*)"[^\n}]*?"class"\s*:\s*"([a-z_]+)"'
)
_SHELL_CLASS = re.compile(
    r"(?m)(?:^|[;&|{])\s*(refused|partial|failed|lock_busy|timed_out)"
    r"\s+([a-z][a-z0-9_]*)\s*(?:;|$)"
)
_CALL = re.compile(r'\b(refused|failed)\("([a-z][a-z0-9_]*)"\)')
_CALL_WITH_CLASS = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*\(\s*"
    r'"(refused|partial|failed|lock_busy|timed_out|succeeded)"\s*,\s*'
    r'"([a-z][a-z0-9_]*)"'
)
_REFUSED_CALL = re.compile(r'\b_refused\(\s*["\']([a-z][a-z0-9_]*)["\']\s*\)')
_EXPORT = re.compile(r'ExportRefused\("([a-z][a-z0-9_]*)"\)')


def printed_pairs(text: str) -> dict[str, set[str]]:
    """The reason names a body text can print, and the classes paired with each."""
    pairs: dict[str, set[str]] = {}

    def add(reason: str, result_class: str) -> None:
        pairs.setdefault(reason, set()).add(result_class)

    for match in _PAIR_CLASS_FIRST.finditer(text):
        add(match.group(2), match.group(1))
    for match in _PAIR_REASON_FIRST.finditer(text):
        add(match.group(1), match.group(2))
    for match in _SHELL_CLASS.finditer(text):
        add(match.group(2), match.group(1))
    for match in _CALL.finditer(text):
        add(match.group(2), match.group(1))
    for match in _CALL_WITH_CLASS.finditer(text):
        add(match.group(2), match.group(1))
    for match in _REFUSED_CALL.finditer(text):
        add(match.group(1), "refused")
    for match in _EXPORT.finditer(text):
        add(match.group(1), "refused")
    return pairs


def _body_declared() -> dict[str, ResultReason]:
    return {
        reason.name: reason
        for declared, _sources in _BODY_VOCABULARIES.values()
        for reason in declared
    }


def _vocabulary_errors(  # noqa: C901 - one walk that reports every drift
    label: str,
    declared: tuple[ResultReason, ...],
    sources: tuple[str, ...],
    shared: Mapping[str, ResultReason] | None = None,
) -> list[str]:
    """Every drift between one declared vocabulary and the composed text it stages."""
    allowed = dict(shared or {})
    allowed.update({reason.name: reason for reason in (*ADMISSION, *declared)})
    errors: list[str] = []
    text_all = ""
    for source in sources:
        path = REPOSITORY / source
        try:
            text = path.read_text()
        except OSError:
            errors.append(f"{source}: body source could not be read.")
            continue
        text_all += text
        for reason, classes in printed_pairs(text).items():
            if reason in RETIRED:
                errors.append(
                    f"{source}: prints retired result reason {reason!r}, which no current "
                    "composer may produce."
                )
                continue
            if reason not in allowed:
                errors.append(
                    f"{source}: prints result reason {reason!r}, which its composer "
                    "does not declare."
                )
                continue
            for result_class in classes:
                try:
                    outcome = Result(result_class)
                except ValueError:
                    continue
                if outcome not in allowed[reason].outcomes:
                    errors.append(
                        f"{source}: reason {reason!r} is paired with {result_class!r}, "
                        "which its declaration does not carry."
                    )
    for declared_reason in declared:
        if declared_reason.name in RETIRED:
            errors.append(
                f"{label}: declares retired reason {declared_reason.name!r}, which no current "
                "body may produce."
            )
        if declared_reason.name not in text_all:
            errors.append(
                f"{label}: composer declares {declared_reason.name!r}, which its body text "
                "cannot print."
            )
    return errors


def admission_errors() -> list[str]:
    """Every reason the engine's own admission prelude can print, declared exactly once."""
    import inspect

    from . import engine

    prelude = "\n".join(
        inspect.getsource(function)
        for function in (engine.payload, engine._backup_step, engine._sites_step)
    )
    printed = set(printed_pairs(prelude))
    expected = {reason.name for reason in ADMISSION}
    errors = [
        f"admission prelude prints {name!r}, which ADMISSION does not declare."
        for name in sorted(printed - expected)
    ]
    errors.extend(
        f"ADMISSION declares {name!r}, which the admission prelude cannot print."
        for name in sorted(expected - printed)
    )
    return errors


def manifest_errors() -> list[str]:
    """Every drift between a declared vocabulary and its composed text.

    Database-free and filesystem-only, so the fast gate can call it on every run. The
    message names the file, reason and outcome that drifted.
    """
    shared = _body_declared()
    errors: list[str] = []
    for slug, declared in _KIND_REASONS.items():
        kind = _KIND_BY_SLUG.get(slug)
        sources = tuple(getattr(kind, "body_sources", ()) or ())
        if kind is not None and sources:
            errors.extend(_vocabulary_errors(slug, declared, sources, shared))
    for name, (declared, sources) in _BODY_VOCABULARIES.items():
        if sources:
            errors.extend(_vocabulary_errors(name, declared, sources, shared))
    errors.extend(admission_errors())
    return errors
