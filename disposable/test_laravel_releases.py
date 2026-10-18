"""A site-owned Laravel release is reconstructed and classified natively.

Phase B (#356): releases belong to the site user beneath the root-controlled
``releases/``, ``current`` is a root-owned link and shared state lives in the site's
private area. Another controller's CI can publish that layout, and a fresh controller
must reconstruct the release, its commit, the branch and the current pointer from the
server's own evidence, and judge the PHP its manifest requires.

The classification (Phase B, #421) runs the body's own function on the server: Caddy
reads only ``current/public`` and the rest of the release stays traversal-only, so this
scenario proves the classification and the site shape agree. The write itself is done
with ``umask 022``, because a release anyone can write is outside the convention.
"""

import shlex

from django.test import tag

from discovery.models import SiteState
from discovery.observations import collect
from discovery.root_read import run_root
from discovery.snapshot import CollectedSnapshot, ObservedRelease, ObservedSite
from laravel import change, observation
from operations.inputs import PreparationInputs
from sites import observation as site_observation
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

    def publish(self, settings: SiteSettings, requirement: str) -> str:
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
install -d -m 0755 "$r" "$r/.git" "$r/public" "$r/bootstrap" "$r/database" "$r/database/migrations"
cat > "$r/artisan" <<'PHP'
<?php
PHP
cat > "$r/public/index.php" <<'PHP'
<?php
PHP
cat > "$r/public/app.css" <<'CSS'
body {{ margin: 0; }}
CSS
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
ln -s "$d/private/laravel.env" "$r/.env"
ln -s "$d/private/storage" "$r/storage"
ln -s "$d/private/cache" "$r/bootstrap/cache"
rm -f "$d/current"
ln -s "releases/{NAME}" "$d/current"
"""
        )
        return f"{settings.directory}/releases/{NAME}"

    def classified(self, settings: SiteSettings, release: str) -> None:
        """Run the body's classification on the server, as the deploy would."""
        source = observation.LARAVEL_SOURCE + (
            "\nclassify(setting("
            f"{settings.identifier!r}, {list(settings.names)!r}, {settings.runtime!r}), "
            f"pathlib.Path({release!r}))\n"
        )
        with self.shell() as shell:
            outcome = run_root(shell, site_observation.python_command(source, ()))
        self.assertEqual(outcome.exit_status, 0, f"{outcome.exit_status}: {outcome.stdout}")

    def metadata(self, path: str) -> str:
        return self.native("stat -c '%U %G %a' " + shlex.quote(path)).strip()

    def site_row(self, found: CollectedSnapshot, settings: SiteSettings) -> ObservedSite:
        sites = [site for site in found.sites.value or () if site.identifier == settings.identifier]
        self.assertEqual(len(sites), 1, "The site was not observed.")
        return sites[0]

    def releases_of(
        self, found: CollectedSnapshot, settings: SiteSettings
    ) -> list[ObservedRelease]:
        return [
            release
            for release in found.releases.value or ()
            if release.identifier == settings.identifier
        ]

    def test_a_site_owned_release_is_reconstructed_and_classified(self) -> None:
        settings = SiteSettings(self.prefix, (self.prefix + ".example.com",), "php84")
        inputs = PreparationInputs(settings.runtime, settings.identifier, settings.names)
        apply_change(self, CREATE_SITE, inputs)
        release = self.publish(settings, "^8.4")
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
        releases = self.releases_of(found, settings)
        self.assertEqual(found.releases.outcome.value, "observed", found.releases.warning)
        self.assertEqual([release_row.name for release_row in releases], [NAME])
        self.assertEqual(releases[0].commit, COMMIT)
        self.assertEqual(releases[0].state, SiteState.MANAGED)
        self.assertTrue(releases[0].current)
        # A checkout leaves the release in the site's own modes with ``public`` open to
        # every account, which is outside the supported Laravel shape until it is
        # classified (#421).
        self.assertEqual(self.site_row(found, settings).state, SiteState.NOT_FOLLOWING)
        self.classified(settings, release)
        self.assertEqual(
            {
                path: self.metadata(path)
                for path in (
                    release,
                    release + "/artisan",
                    release + "/public",
                    release + "/public/app.css",
                    release + "/public/index.php",
                )
            },
            {
                release: f"{settings.account} {settings.account} 711",
                release + "/artisan": f"{settings.account} {settings.account} 600",
                release + "/public": f"{settings.account} caddy 2750",
                release + "/public/app.css": f"{settings.account} caddy 640",
                release + "/public/index.php": f"{settings.account} {settings.account} 600",
            },
        )
        with self.shell() as shell:
            served = collect(shell, releases=True)
        self.assertEqual(self.site_row(served, settings).state, SiteState.MANAGED)
        self.assertTrue(self.releases_of(served, settings)[0].current)
        # The next release's requirement is judged from the same native evidence.
        self.native(
            'printf \'%s\\n\' \'{"require": {"php": "^9.0"}}\' > '
            + shlex.quote(release + "/composer.json")
        )
        with self.shell() as shell:
            deploy = PreparationInputs(identifier=settings.identifier)
            draft = change.review(change.inspect(shell, deploy), deploy)
        self.assertFalse(draft.eligible)
        self.assertTrue(
            any("requires PHP ^9.0" in refusal for refusal in draft.refusals), draft.refusals
        )
        # The classified layout is supported: the review refuses on the requirement, not
        # on the site shape.
        self.assertFalse(
            any("native layout" in refusal for refusal in draft.refusals), draft.refusals
        )
        # A release any account can write leaves the shape again.
        self.native("chmod 0777 " + shlex.quote(release))
        with self.shell() as shell:
            sloppy = collect(shell, releases=True)
        shape = self.site_row(sloppy, settings)
        self.assertEqual(shape.state, SiteState.NOT_FOLLOWING)
        self.assertIn("A site directory has unsupported ownership or permissions.", shape.missing)
