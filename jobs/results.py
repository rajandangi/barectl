"""The one result vocabulary Jobs words and filters with (Phase E #284).

A result class has one filter key, one filter label and one canonical row label. Backup
rows override a label where Phase D's own wording differs, but the class-to-key and
attention mapping lives here and nowhere else.
"""

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class ResultWord:
    result_class: str
    filter_key: str
    filter_label: str
    label: str
    attention: bool


WORDS: Final = {
    "succeeded": ResultWord("succeeded", "finished", "Finished", "Finished", False),
    "partial": ResultWord("partial", "partial", "Partly applied", "Partly applied", True),
    "refused": ResultWord("refused", "refused", "Refused", "Refused", True),
    "failed": ResultWord("failed", "failed", "Failed", "Failed", True),
    "timed_out": ResultWord("timed_out", "timed_out", "Timed out", "Timed out", True),
    "lock_busy": ResultWord(
        "lock_busy",
        "skipped",
        "Skipped",
        "Skipped because other work held the server",
        True,
    ),
    "": ResultWord("", "unconfirmed", "Could not confirm", "Could not confirm", True),
}
RESULT_CHOICES: Final = tuple(
    (word.filter_key, word.filter_label, word.result_class) for word in WORDS.values()
)
ATTENTION: Final = frozenset(word.result_class for word in WORDS.values() if word.attention)

_UNCONFIRMED: Final = WORDS[""]


def word(result_class: str) -> ResultWord:
    """The result's words, with every unknown class read as Could not confirm."""
    return WORDS.get(result_class, _UNCONFIRMED)


def filter_key(result_class: str) -> str:
    return word(result_class).filter_key


def label(result_class: str) -> str:
    return word(result_class).label
