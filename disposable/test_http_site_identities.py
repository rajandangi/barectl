"""Foreign Unix names are refused without adopting or changing their native resources."""

from django.test import tag

from operations.inputs import PreparationInputs
from sites import change

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HttpSiteIdentityAdmission(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s4identity"

    def test_foreign_account_and_group_only_residue_are_refused_without_mutation(self) -> None:
        self.native(
            "groupadd --gid 6000 s4identityprimary; "
            "useradd --uid 6000 --gid s4identityprimary --no-create-home "
            "--home-dir /srv/foreign-native-home --shell /bin/bash ss4identityuser; "
            "groupadd --gid 6001 ss4identitygroup"
        )
        before = self.native("sha256sum /etc/passwd /etc/group /etc/shadow")
        for identifier in ("s4identityuser", "s4identitygroup"):
            inputs = PreparationInputs("php84", identifier, (identifier + ".example.com",))
            with self.shell() as shell:
                draft = change.review(change.inspect(shell, inputs), inputs)
            self.assertFalse(draft.eligible, draft.document)
            self.assertTrue(draft.refusals)
            self.native(
                f"test ! -e /var/www/{identifier}; test ! -e /etc/caddy/sites/{identifier}.caddy"
            )
        self.assertEqual(self.native("sha256sum /etc/passwd /etc/group /etc/shadow"), before)
        self.native("getent passwd ss4identityuser | grep -q /srv/foreign-native-home")
        self.native("getent group ss4identitygroup | grep -q ':6001:'")
