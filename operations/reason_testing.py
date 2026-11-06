"""Shared assertions for the result-reason declarations (#495).

Tests in several apps check the same contract: every declared reason has one sentence for
each outcome it is paired with, the sentence is not the generic class sentence, and the
reason parses from a result line. Keep that loop here so a change to the contract is one
edit, not ten copies.
"""

from collections.abc import Iterable

from django.test import SimpleTestCase

from . import engine, reasons

Vocabularies = Iterable[Iterable[reasons.ResultReason]]


def assert_declared_sentences(
    case: SimpleTestCase,
    vocabularies: Vocabularies,
    *,
    skip_parse: frozenset[str] = frozenset(),
) -> None:
    """Assert the sentence and parser contract for every declared reason and outcome.

    ``skip_parse`` names a staged pause, which the engine deliberately reads past rather
    than treating as the run's result line.
    """
    for vocabulary in vocabularies:
        for reason in vocabulary:
            for outcome in reason.outcomes:
                with case.subTest(reason=reason.name, outcome=outcome.value):
                    sentence = engine.reason_text(outcome.value, reason.name)
                    case.assertEqual(sentence, reason.sentence(outcome))
                    generic = reasons.OUTCOME_SENTENCES.get(outcome)
                    if generic is not None:
                        case.assertNotEqual(sentence, generic)
                    if reason.name in skip_parse:
                        continue
                    line = engine.parse_result_line(
                        f'barectl-result {{"class":"{outcome.value}","reason":"{reason.name}"}}'
                    )
                    if line is None:
                        case.fail(f"Reason {reason.name!r} did not parse.")
                    case.assertEqual(line.reason, reason.name)
