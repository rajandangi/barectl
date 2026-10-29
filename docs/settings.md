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
cached configuration in use, the same apply rebuilds it and restarts the site's running
queue workers; a failed rebuild or worker restart reports partly applied and keeps the
changed environment.

When a Laravel site's object cache is on, `CACHE_STORE`, `REDIS_HOST` and `REDIS_PORT` are
managed by that setting: the table shows them read-only as **Managed by the object cache**,
their values stay on the server, and a review that names one is refused ([object
cache](object-cache.md#laravel-wiring-and-ordering)). Every other key stays editable.

## WordPress settings

The WordPress settings section lists the extra named constants in `private/wp-config.php`.
The values are never shown and are write-only. Barectl owns the fixed part of that file and
refuses these names in the extra block: the eight salts, the database settings, `ABSPATH`,
`DISABLE_WP_CRON` and every `WP_REDIS_*` constant reserved for Phase C
([automation specification](https://github.com/rajandangi/barectl/issues/357)). The three
cache constants (`WP_REDIS_SCHEME`, `WP_REDIS_PATH`, `WP_REDIS_PREFIX`) are written and
removed only by the site's Object cache change, with fixed values, and are never editable
here ([object cache](object-cache.md#wordpress-wiring-and-ordering)).

The same review and confidential-channel path applies. The apply rewrites only the changed
constant lines, leaves the fixed Barectl block and every untouched line byte-identical, and
writes the configuration atomically as the site user at 0600. WordPress's extra constants
must follow a strict uppercase key grammar and a single-quoted string value; a line outside
that grammar is reported as unsupported and is never rewritten.

## Scheduled tasks

A site's **Settings > Scheduled tasks** shows the same state line as its Overview, including **Paused by an unfinished change** and **Background work is off while the site is in maintenance**, with one next action: choosing the state the work should have (the change asks; it never restores a remembered set). A Laravel site's card turns its scheduler on or off and offers **Run now**. Turning on and Run now need a verified Deploy or Roll back outcome for the current release, with no maintenance gate and no pending migrations; turning off is always available. The review states the one-hour run limit, the no-catch-up behaviour and the sub-minute and `runInBackground` limits in plain words ([automation](automation.md#turning-the-laravel-scheduler-on-and-off-and-run-now)).

## Backup storage

Server **Settings > Backup storage** shows the offsite provider, bucket and region or
account endpoint read from the server, or offers the two supported templates: Amazon S3 and
Cloudflare R2. Setting it up and removing it are reviewed Shared changes that also need
`operations.manage_secrets`; the access keys and the recovery passphrase are typed on the
confirmation screen and travel only through the confidential input channel. They are written
to root-owned `0600` files on the server and never stored in Barectl's database. Opening the
section makes no SSH connection. A setting outside the supported template is shown as
**Outside supported settings** and blocks only backup changes for the server's sites.

The setup review names the bucket, the region or account endpoint, whether a separate S3
pruning key is used, and that object lock and immutability are not configured. The removal
review says plainly that copies already in the bucket stay there. The storage and copy controls are described in
[backups](backups.md#offsite-storage); replacing the recovery passphrase remains planned in
the [Phase D specification](https://github.com/rajandangi/barectl/issues/358).

## Permissions and discovery

Preparing either change needs the site-change permissions and the separate
`operations.manage_secrets` permission; applying rechecks the same permission with the
review's consent. A fresh controller reads the key names and server-computed digests during
full discovery. The stored observation never contains a secret value, and no page, command,
unit property, journal line, run record or response receives one.
