# Own every site release as the site user

Accepted on 2026-10-30 for [#401](https://github.com/rajandangi/barectl/issues/401). Phase B's
convention made a Laravel release site-owned and traversal-only (`0711`), while a plain or
WordPress site kept the placeholder `releases/initial` root-owned `0755`. Phase D restores files
into "a new release directory in #356's site-owned release form, owned by the target site user"
([#358](https://github.com/rajandangi/barectl/issues/358)), and `#401` requires restored files to
be owned by the site user whatever the archive recorded. A root-owned release would make a
restore visibly different from a Create or Deploy and leave the release entry outside the site
user's ownership.

Create and Restore now both publish `releases/initial` and every restored
`releases/restore-<point>-<token>` as `site user:site group 0711`, with `public/` at
`site user:caddy 2750`; Deploy already classifies its Laravel release the same way
([ADR 0040](0040-classify-laravel-release-permissions.md)). Only `releases/` itself stays
root-owned, so the site user cannot add a release entry. Discovery accepts the site-owned form
for every site kind and still recognizes the earlier root-owned `0755` release on existing
sites, so an upgrade does not report a working site as outside supported settings.

The alternative was to leave plain and WordPress releases root-owned and make only their
contents site-owned. That would keep the old recognizer, but the restored release entry would
not belong to the site user, and the same site would look different depending on whether it
arrived through Create, Deploy or Restore. The cost is re-recording the shared site transcripts,
which this change does on the native lane.
