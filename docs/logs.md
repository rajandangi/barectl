# Site logs

Barectl reads a site's own logs on request and keeps each log rotated. The managed server is
the source of truth: pages are temporary, controller-local rows, and no marker or inventory
of log content lives on the server.

## Catalogue

The Logs section of a site lists a fixed catalogue by plain name:

| Name | Native source | Rotation |
| --- | --- | --- |
| Visits | Caddy's JSON access log in the site's log directory | Caddy (`roll_size 20MiB`, `roll_keep 5`, `roll_keep_for 14d`) |
| PHP errors | the site pool's `error_log` | Barectl's per-site logrotate file |
| Slow PHP requests | the site pool's `slowlog` | Barectl's per-site logrotate file |
| Application log | a Laravel site's daily `laravel-YYYY-MM-DD.log` files in shared private storage | Laravel's daily channel (`LOG_DAILY_DAYS=14`) |
| WordPress debug log | the site's `wp-debug.log` when WordPress debugging is pointed into the log directory | Barectl's per-site logrotate file |

A log that does not exist is still part of the catalogue and reads as **missing** rather
than disappearing. The WordPress debug log is listed for a WordPress site; the read reports
it as missing until the operator enables it.

## Reading

A read is a Read-consent remote operation (`logs.LogRead`), not a change review: it occupies
the server's one operation slot, runs in `db_worker`, and connects through
`discovery.ssh.connect` and `RemoteShell` like every other remote step. Opening the Logs
section or a stored page queues nothing and issues no SSH.

One fixed command per read runs under the shared native read lock and returns one page:

- at most **500 lines** and **256 KiB** of log text;
- one Caddy access line is at most 8 KiB, marked shortened when cut;
- the answer is gzip-compressed and base64-encoded because one SSH command may carry only
  64 KiB; a page that would not fit is shortened from its oldest end, never by loading the
  whole file;
- the read scans at most 1 MiB before the cursor, so a huge file never fills the controller;
- older pages continue from an opaque cursor of file identity (device, inode, name) and byte
  offset; a cursor into a replaced or truncated file reads as **rotated**;
- a plain search term and a time range filter the scanned window. The time range uses each
  line's own timestamp where it has one (Caddy's `ts`, a leading `YYYY-MM-DD HH:MM:SS`, or
  PHP's `[DD-Mon-YYYY HH:MM:SS]`), and selects Laravel's daily files by date.

The read distinguishes exactly:

| State | What the operator sees |
| --- | --- |
| `observed` | The page, oldest line first |
| `missing` | "This log does not exist yet." |
| `empty` | "This log exists and is empty." (or "No lines match the filter") |
| `unreadable` | "This log exists but Barectl may not read it." or another fixed reason |
| `rotated` | "This log rotated since the last page. Read the newest lines again." |

Access entries render as time, method, path, status and duration, with the raw line in a
one-click disclosure. Every other source renders each raw line.

A request stores its typed page (`state`, lines, cursor, file names, rotation evidence) only
on its own row. The page is deleted after **24 hours**, and the previous page of the same log
is deleted when that log is read again.

## Secret scrubbing

Before any line leaves the server, the fixed read command reads the site's current private
configuration — `private/laravel.env`, or the `define()` constants in
`private/wp-config.php` — and replaces every secret value it holds with `<secret>`. Only a
regular, non-symlink file owned by the site account with no group or other permission is
read. A key participates when its name contains `PASSWORD`, `SECRET`, `TOKEN`, `KEY` or
`SALT`; a value must be at least 4 characters. The controller never receives the values.

The controller then passes every stored page line through the same
`operations.confidential.scrub` chokepoint. A read carries no submitted secret, so that pass
has no values today; it keeps a future source from opening a second path to storage. The
fast tests carry canary values through the real server-side read into the stored page and
the rendered HTML.

## Permission

Reading a site's logs needs `operations.view_evidence`, granted to the **Site operator** and
**Administrator** presets and not to **Viewer**. A Viewer who can see the site still reaches
the Logs section and reads an explanation; the section is not a 404. A direct read POST
without the permission is refused with 403. Site visibility keeps its
`discovery.view_siteobservation` gate.

## Rotation

Barectl owns one root-owned file per site, `/etc/logrotate.d/barectl-site-<identifier>`:

```text
/var/www/<id>/logs/php-error.log /var/www/<id>/logs/php-slow.log [/var/www/<id>/logs/wp-debug.log] {
    daily
    maxsize 20M
    rotate 5
    maxage 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 s<id> s<id>
}
```

It covers only logs Barectl creates in the site's log directory. Caddy's access log is
excluded because Caddy rotates it, and Laravel's daily channel rotates its own files.

The file is installed by every create path (Create site, Create WordPress site, Create
Laravel site) after the layout exists. A host without the logrotate package keeps its site;
the file is absent and the Logs section says the server does not run logrotate. For a site
created earlier, or whose file was edited outside the supported shape, the Logs section
offers the reviewed **Set up log rotation** change (`set_up_log_rotation`, Site consent). It
publishes only the reviewed text, after `logrotate --debug` accepts it; failure leaves the
previous file and nothing else changes.

**Why the file rotates as root.** The site log directory is `caddy:site 0750`. logrotate's
`su` runs the whole rotation as the named account, which cannot rename or create files in a
directory where its group has no write permission. The supported file therefore rotates as
root and recreates each file with `create 0640 s<id> s<id>`, preserving the directory
convention and the site's ownership. This is a deliberate deviation from the Phase C
specification's `su` wording, recorded on #389; the alternative (an ACL for the site account
on the log directory) adds an unobserved permission and another package dependency.

## Recognition and evidence

The supported rotation shape is rendered and parsed by `sites/bodies/logrotate.py`: a file
that matches the fixed header, directives and known paths for its own site is supported;
anything else is outside the supported settings. Discovery stores the state in the site
observation's typed `log_rotation` column (ADR 0003): `supported`, `partial`, `outside`,
`missing`, or `unavailable` when the server does not run logrotate. The Logs section states
it once, next to **Set up log rotation** when the state is not supported; every log page and
the reviewed action carry the same typed evidence.

The site read gained the column, so every stored transcript that contains a site read was
re-recorded with the documented recorder. The later #394 merge may need one consolidated
re-record on the integration tree; do not hand-edit transcript JSON.

## Tests

- `logs/test_read.py` proves the server-side page bounds, cursors, states, filters, access
  rendering and canary scrubbing against a temporary tree.
- `logs/test_logs.py` proves the read operation, stored pages, 24-hour and next-read
  deletion, the permission explanation, the rotation review and body, and the presets.
- `logs/test_browser.py` reaches a PHP error line from a site page in two activations.
- `disposable/test_logs_validators.py` proves the rendered file passes `logrotate --debug`
  and a broken directive does not.
- A manual disposable-container check proved the rotation itself: root rotates
  `php-error.log` in the `caddy:site 0750` directory, `create 0640 site site` recreates it
  with the site's ownership, and a second forced run compresses `.1` to `.1.gz` under
  `delaycompress`. The L0/L1 image carries no logrotate package today, and installing it in
  a lifecycle scenario changes the host's observed standing (apt maintenance and the L2
  prepared site's HAProxy); the automated end-to-end rotation scenario is therefore not
  included, and this is recorded as unrun in `notes/handoff-389.md`. The mirror now carries
  the `logrotate` package so the validator can install it.

## Later: journal sources

#397 adds the journal of each automation unit and Valkey instance. Add its sources to
`logs.sources.CATALOGUE` and `logs.bodies.read.SOURCES`, give the server-side reader a
`journalctl -u <unit> --cursor/--after-cursor` path that returns the same page shape and
cursor, and keep the controller's `LogSource` slug stable. The operation, storage, cleanup,
permission and viewer seams do not change.
