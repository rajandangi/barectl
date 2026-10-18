"""A release laid out the way the convention describes is reconstructed natively.

Phase B (#356): releases belong to the site user beneath the root-controlled
``releases/``, ``current`` is a root-owned link and shared state lives in the site's
private area. Another controller's CI can publish that layout, and a fresh controller
must reconstruct the release, its commit, the branch and the current pointer from the
server's own evidence, and judge the PHP its manifest requires.

The write is done with ``umask 022`` and the release stays unreadable to other accounts;
a release anyone can write is not a release the convention accepts (asserted in the fast
layer). The permission classification of a Laravel release (a Caddy-readable public root
and a closed rest) belongs to the Laravel site convention, so the scenario leaves the
checkout's own modes in place.
"""

import shlex

from django.test import tag

from discovery.models import SiteState
from discovery.observations import collect
from laravel import change, observation
from operations.inputs import PreparationInputs
from sites.change import CREATE_SITE
from sites.configuration import SiteSettings

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

REPOSITORY = "https://github.com/example/app.git"
COMMIT = "a" * 40
TOKEN = "b" * 16
NAME = f"{COMMIT}-{TOKEN}"


@tag(SCENARIO_TAG)
class LaravelReleaseReconstruction(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s4releases"

    def publish(self, settings: SiteSettings, requirement: str) -> None:
        """Create the release another controller's CI would leave, as the site user's code."""
        directory = shlex.quote(settings.directory)
        release = shlex.quote(f"{settings.directory}/releases/{NAME}")
        account = shlex.quote(settings.account)
        self.native(
            f"""set -eu
umask 022
d={directory}
r={release}
a={account}
install -d -m 0755 "$r" "$r/.git" "$r/public" "$r/database" "$r/database/migrations"
cat > "$r/artisan" <<'PHP'
<?php
PHP
cat > "$r/public/index.php" <<'PHP'
<?php
PHP
cat > "$r/composer.json" <<'JSON'
{{"require": {{"php": "{requirement}"}}}}
JSON
cat > "$r/.git/config" <<'GIT'
[remote "origin"]
\turl = {REPOSITORY}
GIT
cat > "$r/.git/HEAD" <<'GIT'
ref: refs/heads/main
GIT
chown -R "$a:$a" "$r"
install -d -o "$a" -g "$a" -m 0700 "$d/private/storage" "$d/private/cache"
install -o "$a" -g "$a" -m 0600 /dev/null "$d/private/laravel.env"
rm -f "$d/current"
ln -s "releases/{NAME}" "$d/current"
"""
        )

    def test_a_site_owned_release_layout_is_discovered_and_current(self) -> None:
        settings = SiteSettings(self.prefix, (self.prefix + ".example.com",), "php84")
        inputs = PreparationInputs(settings.runtime, settings.identifier, settings.names)
        apply_change(self, CREATE_SITE, inputs)
        self.publish(settings, "^8.4")
        with self.shell() as shell:
            row = observation.site(observation.read(shell) or {}, settings.identifier)
            found = collect(shell, releases=True)
        if row is None:
            self.fail("The site's release layout was not read.")
        self.assertEqual(row["application"], "laravel", repr(row))
        self.assertEqual(row["current"], NAME)
        self.assertEqual(row["repository"], REPOSITORY)
        self.assertEqual(row["branch"], "main")
        self.assertEqual(row["php_requirement"], "^8.4")
        self.assertEqual(row["shared"], {"environment": True, "storage": True, "cache": True})
        releases = [
            release
            for release in found.releases.value or ()
            if release.identifier == settings.identifier
        ]
        self.assertEqual(found.releases.outcome.value, "observed", found.releases.warning)
        self.assertEqual([release.name for release in releases], [NAME])
        self.assertEqual(releases[0].commit, COMMIT)
        self.assertEqual(releases[0].state, SiteState.MANAGED)
        self.assertTrue(releases[0].current)
        # The next release's requirement is judged from the same native evidence.
        self.publish(settings, "^9.0")
        with self.shell() as shell:
            deploy = PreparationInputs(identifier=settings.identifier)
            draft = change.review(change.inspect(shell, deploy), deploy)
        self.assertFalse(draft.eligible)
        self.assertTrue(
            any("requires PHP ^9.0" in refusal for refusal in draft.refusals), draft.refusals
        )
