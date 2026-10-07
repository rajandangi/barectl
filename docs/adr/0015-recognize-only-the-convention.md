# Recognize only the convention, and judge resources by their shape

Accepted. Implementation and final verification are tracked in [#193](https://github.com/rajandangi/barectl/issues/193) and the [convention qualification record](../convention-qualification.md). Discovery reads Barectl's own layout and nothing more general. A site, pool, package set, database or role is managed when its native evidence matches the convention exactly, whoever made it. Anything else is reported as one item that does not follow the convention, naming the file or resource and what Barectl expects there, and Barectl changes nothing that depends on it. The rest of the server stays manageable. The server stays the source of truth: there is no server-side manifest and no record of who created a resource.

## Rules

- First connection and every later discovery apply the same rule; a server is never refused as a whole because one resource does not match.
- A non-matching site is blocked and explained. An operator brings it into the convention by ordinary administration, guided by the message; the next discovery recognizes it. Barectl does not convert foreign configuration.
- Creating a site next to a non-matching one reads only the server names that other enabled files declare, and refuses a name already in use. No other value is interpreted from a foreign file.
- A Barectl site whose files later differ is reported once as changed outside Barectl, naming the file, and is locked until it matches again. The individual differences are not described.
- Installed packages that match a bootstrap profile are accepted however they were installed; others are reported with what to remove or change.
- A database or role that matches a binding is accepted; any other state of a convention-named database or role is reported, not described difference by difference.
- PostgreSQL is the supported release's default major with its `main` cluster.
- A site left partly applied by a Barectl run has Barectl's own shape and may be finished by a new reviewed plan that creates only what is missing.

## Consequences

- Supersedes the parts of [ADR 0009](0009-review-native-file-changes-before-site-mutation.md), [ADR 0012](0012-publish-site-files-without-replacing-them.md#compensation) and [ADR 0013](0013-create-a-database-binding-statement-by-statement.md) that forbid resuming a partly applied run. Finishing still never replaces or removes an existing resource.
- Foreign files are not read for a shared socket, document root, certificate or default server. A new site still requires its own convention paths to be absent, and only server names are compared with foreign files.
- The generic Nginx site file and PHP-FPM pool listings leave the server page.
- Per-site PHP versions need a package source beyond the Ubuntu archive. [Accepted ADR 0016](0016-limit-third-party-php-supply.md) records the upstream guidance and source terms; implementation and qualification remain pending.
