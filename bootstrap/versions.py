"""Debian package version ordering, as Debian Policy 5.6.12 defines it."""

import re

_PART = re.compile(r"(\D*)(\d*)")


def compare(first: str, second: str) -> int:
    """Negative, zero or positive as ``first`` sorts before, with or after ``second``."""
    first_epoch, first_upstream, first_revision = _split(first)
    second_epoch, second_upstream, second_revision = _split(second)
    if first_epoch != second_epoch:
        return first_epoch - second_epoch
    return _compare_part(first_upstream, second_upstream) or _compare_part(
        first_revision, second_revision
    )


def _split(version: str) -> tuple[int, str, str]:
    epoch, _, rest = version.partition(":") if ":" in version else ("0", "", version)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch), upstream, revision


def _compare_part(first: str, second: str) -> int:
    first_parts, second_parts = _parts(first), _parts(second)
    for index in range(max(len(first_parts), len(second_parts))):
        first_text, first_number = first_parts[index] if index < len(first_parts) else ("", 0)
        second_text, second_number = second_parts[index] if index < len(second_parts) else ("", 0)
        if order := _compare_text(first_text, second_text):
            return order
        if first_number != second_number:
            return first_number - second_number
    return 0


def _parts(value: str) -> list[tuple[str, int]]:
    return [(text, int(number or 0)) for text, number in _PART.findall(value) if text or number]


def _compare_text(first: str, second: str) -> int:
    for index in range(max(len(first), len(second))):
        first_weight = _weight(first[index]) if index < len(first) else 0
        second_weight = _weight(second[index]) if index < len(second) else 0
        if first_weight != second_weight:
            return first_weight - second_weight
    return 0


def _weight(character: str) -> int:
    if character == "~":
        return -1
    if character.isalpha():
        return ord(character)
    return ord(character) + 256
