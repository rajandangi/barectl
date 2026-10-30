"""The source files whose text is embedded in a recorded native transcript.

A change to one of these files changes a fixed read or body command that transcripts replay.
The checked-in manifest lets the fast layer name the stale evidence and the one command that
re-records it, before a replay fails with an unrecorded command
(docs/quality.md#recorded-transcripts).
"""

import hashlib
import json
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
MANIFEST = Path(__file__).resolve().with_name("transcript_sources.json")
FORMAT = 1

# Shared native reads and body sources. A transcript may embed only some of them, but every
# one can change a command a transcript holds; record all states when any changes.
SOURCES = (
    "automation/bodies/observe.py",
    "backups/bodies/observe.py",
    "databases/binding.py",
    "automation/bodies/observe_workers.py",
    "automation/bodies/source.py",
    "automation/bodies/units.py",
    "automation/convention.py",
    "automation/workers.py",
    "bootstrap/standing.py",
    "cache/convention.py",
    "cache/instance.py",
    "discovery/observations/__init__.py",
    "discovery/observations/components.py",
    "discovery/observations/probes.py",
    "discovery/observations/standing.py",
    "discovery/snapshot.py",
    "laravel/observation.py",
    "logs/read.py",
    "operations/apt.py",
    "runtimes/observation.py",
    "security/observation.py",
    "sites/bodies/admission.py",
    "sites/bodies/common.py",
    "sites/bodies/logrotate.py",
    "sites/bodies/node.py",
    "sites/bodies/php_runtime.py",
    "sites/bodies/pool.py",
    "sites/bodies/site_fpm.py",
    "sites/observation.py",
    "wordpress/observation.py",
)


def digests() -> dict[str, str]:
    """The current digest of every shared source, keyed by repository-relative path."""
    return {path: hashlib.sha256((REPOSITORY / path).read_bytes()).hexdigest() for path in SOURCES}


def read() -> dict[str, str]:
    """The recorded manifest, validated as it is read."""
    document = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != FORMAT:
        raise ValueError(f"{MANIFEST.name} is not a format {FORMAT} manifest.")
    sources = document.get("sources")
    if not isinstance(sources, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in sources.items()
    ):
        raise ValueError(f"{MANIFEST.name} does not hold a source digest map.")
    return sources


def write() -> Path:
    """Write the current digest map; run after `scripts/record-all-transcripts.sh`."""
    MANIFEST.write_text(
        json.dumps({"version": FORMAT, "sources": dict(sorted(digests().items()))}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    return MANIFEST


def stale() -> tuple[str, ...]:
    """The shared sources whose digest differs from the recorded manifest."""
    recorded = read()
    current = digests()
    return tuple(
        sorted(
            path for path in set(recorded) | set(current) if recorded.get(path) != current.get(path)
        )
    )


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["write"]:
        print(write())  # noqa: T201
        return 0
    if arguments:
        print("usage: python -m discovery.source_manifest [write]", file=sys.stderr)  # noqa: T201
        return 2
    changes = stale()
    for path in changes:
        print(path)  # noqa: T201
    return 1 if changes else 0


if __name__ == "__main__":
    raise SystemExit(main())
