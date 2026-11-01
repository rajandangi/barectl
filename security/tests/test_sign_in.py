"""The reviewed SSH sign-in kind at its inspect, review, body and verify seams (#308)."""

from dataclasses import replace
from unittest import mock

from django.test import SimpleTestCase

from discovery.models import ObservationOutcome
from discovery.snapshot import Observation
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.inputs import PreparationInputs
from operations.models import Consent
from security import observation, sign_in
from security.observation import Check, SshState
from security.testing import ok_state

BOOT = "0123456789abcdef0123456789abcdef"
UNIT = "barectl-apply-" + "a" * 32 + ".service"


def _state(*, passwords: str = "yes", overrides: tuple[str, ...] = ()) -> SshState:
    return SshState(
        passwords,
        "no",
        "prohibit-password",
        (22,),
        (22,),
        ("deploy",),
        "yes",
        (22,),
        overrides,
        True,
        True,
        ("deploy", "root"),
    )


def _evidence(*, state: SshState | None = None, user: str = "root") -> sign_in.SignInEvidence:
    return sign_in.SignInEvidence(
        state or _state(),
        "Target stack",
        BOOT,
        500000,
        "a" * 64,
        user,
        True,
        "192.0.2.4",
        "192.0.2.8",
        "22",
        ("alpha", "beta"),
    )


class SignInReviewTests(SimpleTestCase):
    def test_weak_sign_in_is_shared_and_warns_about_accounts_without_keys(self) -> None:
        draft = sign_in.review(_evidence(), PreparationInputs("on"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SERVER])
        self.assertEqual(draft.effects[0].sites, ("alpha", "beta"))
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertIn("deploy", str(draft.document["details"]))
        self.assertIn("5-minute window", str(draft.document["details"]))
        native = sign_in.body(draft.document, BodyContext(UNIT, BOOT, 500100))
        self.assertIn(b"sshd -t", native.source)
        self.assertIn(b"systemctl reload ssh.service", native.source)
        self.assertIn(b"sshd -T -C", native.source)
        self.assertIn(b"--on-active=300", native.source)
        self.assertIn(b"PermitRootLogin %s", native.source)
        self.assertEqual(native.arguments[-1], "a" * 32)

    def test_non_root_sudo_connection_disables_root_login(self) -> None:
        draft = sign_in.review(_evidence(user="operator"), PreparationInputs("on"))
        self.assertEqual(draft.document["root_policy"], "no")

    def test_no_change_only_when_global_and_match_policy_hold(self) -> None:
        draft = sign_in.review(_evidence(state=_state(passwords="no")), PreparationInputs("on"))
        self.assertTrue(draft.no_changes)
        conflict = sign_in.review(
            _evidence(state=_state(passwords="no", overrides=("deploy",))),
            PreparationInputs("on"),
        )
        self.assertFalse(conflict.no_changes)
        self.assertIn("deploy", str(conflict.document["details"]))

    def test_unreadable_accounts_refuse_before_a_body_is_submitted(self) -> None:
        evidence = _evidence(state=replace(_state(), accounts_readable=False))
        draft = sign_in.review(evidence, PreparationInputs("on"))
        self.assertFalse(draft.eligible)
        self.assertIn("every login account", str(draft.refusals))

    def test_a_modified_review_is_refused(self) -> None:
        draft = sign_in.review(_evidence(), PreparationInputs("on"))
        document = dict(draft.document)
        document["accounts"] = ["root;rm -rf /"]
        with self.assertRaises(ValueError):
            sign_in.body(document, BodyContext(UNIT, BOOT, 500100))


class SignInVerificationTests(SimpleTestCase):
    def test_effective_match_override_fails_verification(self) -> None:
        draft = sign_in.review(_evidence(), PreparationInputs("on"))
        stored = mock.Mock(document=draft.document)
        state = replace(
            ok_state(),
            ssh=Check(
                ObservationOutcome.OBSERVED, (), "", _state(passwords="no", overrides=("deploy",))
            ),
        )
        with mock.patch.object(
            observation,
            "collect",
            return_value=Observation(ObservationOutcome.OBSERVED, (), "", state),
        ):
            self.assertFalse(sign_in.verify(mock.Mock(), stored))
