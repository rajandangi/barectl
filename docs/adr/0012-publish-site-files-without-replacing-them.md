# Publish site files without replacing them, and report each boundary

A site run creates an account, directories, files and a link, and reloads two services. These cannot form one transaction, so the payload publishes each file in a way that can fail but never replaces anything, reports how far it got by its exit status, and compensates only the two steps whose after-state it can prove it made. Implemented in `sites/native.py` (the payload) and `sites/apply.py` (outcomes and verification); qualified on the disposable Ubuntu 24.04 and 26.04 servers ([qualification](../v0.3-qualification.md#site-creation)).

## Publication

The payload runs under the mutation lock of [ADR 0006](0006-use-native-bootstrap-execution.md) with `umask 077` and `set -C`. Every value the payload interpolates is checked when it is built: each file's path, owner, group and mode must be the convention's for the site, and its bytes the convention's template, or nothing is submitted. Before staging, and again immediately before publishing, the destination directory and every directory above it up to `/` must be root's, not symbolic links, and writable by nobody else; a directory's group may be another, as the document root's `www-data` is. Every file is then written to a stage beside its destination, named `.<name>.<32 hex digits of the unit>`, which neither Nginx's `sites-enabled/*` nor PHP-FPM's `pool.d/*.conf` includes. The stage gets its reviewed owner and mode, is synced, and its SHA-256 must equal the reviewed digest. Only while the destination is still neither a file nor a link does `ln -T` hard-link the stage into place: `link(2)` fails rather than replacing anything that appeared since revalidation, and `-T` prevents writing into a directory put in its place. The stage is then removed and the directory synced. The enablement link is made the same way with `ln -sT`. A stage whose publication failed stays for inspection.

A creation plan replaces nothing: its review requires every destination to be absent, so no preimage backup is made.

The account is created with the reviewed `useradd` command and its explicit flags, one definition for the review and the payload, under useradd's own lock; its actual IDs are read back and must match the review before any ownership uses them.

## Replacement

A challenge route replaces the site file in place ([TLS](../tls.md#applying)), the first action that does. The reviewed preimage's SHA-256 is rechecked under the lock with the file's type, owner, mode and single link; the file is then copied to a root-only backup named after the run's unit, whose bytes must equal the preimage's. The candidate is staged beside the file as `.<name>.<unit>`, checked against its reviewed digest, and renamed over the file with `mv -T` only while the file still has the preimage's bytes and every directory above it is root's; otherwise the stage is removed and the file kept. If `nginx -t` refuses the candidate, a staged copy of the backup is renamed back while the file still has the candidate's bytes, `nginx -t` runs again, and nothing is reloaded. The backup is kept after success and failure; it is recovery material an administrator uses, never evidence Barectl reads as current state.

## Order

The pool is published, checked with `php-fpm -t` and loaded first, and its socket must exist, owned by `www-data` with mode 0600 and listening, before the Nginx site file and link are published. The PHP runtime identity is proven afterwards, through the enabled site, by the temporary probe, whose answer must be the site user's IDs before the run can succeed. This is how the specification's "verify the pool, socket and identity before the site entry" is met: the socket before the entry, the identity before success.

## Boundaries

After the admission exits of ADR 0006, exit 15 means nothing was changed because the reviewed site digest differs, a destination exists, a parent directory is unsafe, or `useradd`, `nginx`, `php-fpm` or the PHP CLI is missing. Each later exit status names the boundary the run reached. 31 means useradd failed and the account databases are unchanged; it is a refusal before changes. 40 to 55 are partial completion: 40 useradd failed after the databases changed, 41 the account differs from the review, 42 directories, 43 content, 44 the pool file, 45 the pool withdrawn with a valid configuration, 46 an invalid configuration, 47 the PHP-FPM reload, 48 the socket, 49 the site file, 50 the link, 51 the link withdrawn with a valid configuration, 52 an invalid configuration, 53 the Nginx reload, 54 not serving as reviewed, 55 the probe left. The run keeps the raw exit status; the pages turn it into what exists and the ordinary administration that completes or removes it ([recovering a partial site](../sites.md#recovering-a-partial-site)). A killed wrapper, a timeout or a reboot leaves the boundary unknown; a new review shows the current state.

## Compensation

Only two changes are undone, both under the lock and only while their after-state is still the run's own: a pool file that `php-fpm -t` rejects is removed if it still has the reviewed bytes, owner and mode, before any reload; a link that `nginx -t` rejects is removed if it is still root's and points to the reviewed file. Either is followed by the same syntax check. Nothing is undone after a reload. Accounts, directories, content and anything an operator or application wrote are never removed, and no run is resumed, replayed or adopts an existing resource. The exact temporary probe is removed while its bytes still match, on success and before any later failure exits; a changed probe, or one that cannot be removed, is kept, and the run exits 55, incomplete verification, whatever boundary it had reached.

## Limit

The lock is cooperative. It excludes Barectl runs from every controller and alias of a server, and the payload rechecks every destination and its directory immediately before publishing, but a root administrator writing outside the lock between that check and the publication is not serialized.
