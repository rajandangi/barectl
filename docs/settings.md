# Settings and secrets

Barectl edits a site's private configuration from the dashboard without keeping a secret in
the controller ([ADR 0032](adr/0032-keep-secrets-in-private-native-files.md)). A Laravel site's
**Environment** section and a WordPress site's **WordPress settings** section follow the same
rule: the authoritative copy lives in the site's private file as the site user, values are
write-only in the interface, and only the reviewed keys change.

## Laravel environment

A Laravel site's Environment section lists the key names in `private/laravel.env`. The site's
own `APP_URL`, `APP_ENV`, `APP_NAME`, `APP_DEBUG`, `APP_LOCALE`, `APP_FALLBACK_LOCALE`,
`LOG_CHANNEL`, `LOG_LEVEL`, `LOG_DAILY_DAYS`, `CACHE_STORE`, `QUEUE_CONNECTION`,
`SESSION_DRIVER`, `SESSION_LIFETIME` and the database connection keys except `DB_PASSWORD` show their values; every other value is
masked. Discovery reads the key names and a SHA-256 digest of each server-side value, never a
secret value, so the dashboard opens from the latest observation without an SSH call and a
fresh controller reconstructs the same key list.

**Change** and **Remove** prepare one Site review. The review names the key and its action,
never a new value. The confirm screen asks for the new value, which reaches the worker only
through the confidential input channel and is sealed into the run until it is sent. The apply
runs under the site lock, rewrites only the reviewed lines, leaves every untouched line
byte-identical, and writes the file atomically as the site user at 0600. When Laravel has a
cached configuration in use, the same apply rebuilds it; a failed rebuild reports partly
applied and keeps the changed environment.

## WordPress settings

The WordPress settings section lists the extra named constants in `private/wp-config.php`.
The values are never shown and are write-only. Barectl owns the fixed part of that file and
refuses these names in the extra block: the eight salts, the database settings, `ABSPATH`,
`DISABLE_WP_CRON` and every `WP_REDIS_*` constant reserved for Phase C
([automation specification](https://github.com/rajandangi/barectl/issues/357)).

The same review and confidential-channel path applies. The apply rewrites only the changed
constant lines, leaves the fixed Barectl block and every untouched line byte-identical, and
writes the configuration atomically as the site user at 0600. WordPress's extra constants
must follow a strict uppercase key grammar and a single-quoted string value; a line outside
that grammar is reported as unsupported and is never rewritten.

## Permissions and discovery

Preparing either change needs the site-change permissions and the separate
`operations.manage_secrets` permission; applying rechecks the same permission with the
review's consent. A fresh controller reads the key names and server-computed digests during
full discovery. The stored observation never contains a secret value, and no page, command,
unit property, journal line, run record or response receives one.
