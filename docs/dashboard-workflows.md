# Dashboard workflows

The dashboard organizes work around managed servers and their sites. This document describes the current operator workflows: navigation, connection states, review boundaries, what continues without the controller, and recovery. The result is plain PHP hosting over HTTPS on the [target stack](target-architecture.md): a site with its own Linux user, PHP-FPM master, private HAProxy admission and Caddy site file that Caddy serves over HTTPS, plus reviewed Laravel Deploy and Roll back over an existing Laravel release layout ([sites](sites.md#deploying-a-laravel-site)). Barectl does not create Laravel sites, manage databases, turn HTTPS on for an existing HTTP-only site, monitor sites, roll changes back automatically or manage DNS records.

## Server navigation

The global navigation is **Servers**, **Sites** (every observed site across servers) and **Activity**. **Add server** saves a connection and queues a connection check ([saved server connections](saved-server-connections.md)). Credentials and host trust stay on the controller host; Barectl offers no browser key upload or host-trust bypass.

| Section | Stable URL | What it holds |
| --- | --- | --- |
| Overview | `/servers/<pk>/` | The recorded connection outcome and observation time, host standing with its named reasons and foundation stages, platform and capacity, connection remediation and the next action. **Needs attention** lists each host finding, unfinished foundation, unreadable site configuration, site outside supported settings or partly applied, and failed PHP runtime with its one next action: Set up server, finish the runtime change, inspect the unavailable evidence, inspect PHP runtimes, or correction through ordinary administration followed by discovery. Not manageable hosts stay read-only. |
| Sites | `/servers/<pk>/sites/` | Observed sites, led by their domain names, each linking to its site pages, and **Create HTTP site** on a Target stack host ([creating a PHP site](sites.md)). |
| Stack | `/servers/<pk>/stack/` | Web (Caddy evidence and every site file as Recognized, Outside supported settings, Absent or Not confirmed), PHP runtimes (master state, protections read back and every site pool), Defaults, Runtime catalog and Services. Recognized includes hand edits within supported settings. A pool is Not confirmed when another finding stopped the reader before it reached the pool. |
| Setup | `/servers/<pk>/setup/` | **Set up server** for a Fresh host or an Incomplete foundation ([setting up a server](bootstrap.md)). Shown to accounts that may prepare changes. |
| Changes | `/servers/<pk>/changes/` | The server's reviews and runs, and the reviewed cleanup of finished runs. Needs `operations.view_changes`. |
| Activity | `/servers/<pk>/activity/` | This registration's discovery attempts, reviews and runs, joined by the registration, never by a matching name or address. |
| Advanced | `/servers/<pk>/advanced/` | The stored discovery evidence in technical detail: commands read, outcomes and warnings. |

Each page keeps the server's name and a return to Servers. Sections are ordinary links that support direct loading, reload and browser back and forward. Section visibility follows viewing permissions; a hidden control never replaces authorization on the destination request.

Navigation reads stored observations and local records. Opening a page, including Overview's host standing, makes no SSH connection. Only CSRF-protected POSTs queue work.

## Connection states and next actions

Next-action guidance describes what the recorded evidence suggests. It is not an eligibility check: preparation, the immutable review, native locking and fresh revalidation decide whether a change can run.

| Recorded state or evidence | Operator guidance | Authority and limits |
| --- | --- | --- |
| Empty server inventory | Offer **Add server** to an authorized operator. | Needs `servers.view_server` and `servers.add_server`. |
| Not verified, no successful snapshot | Check the connection before relying on observations. | A check needs `discovery.add_discoveryattempt`. |
| Check queued | Show the queued time and how to start the worker if it stays queued. | No duplicate check while the server's operation slot is occupied. |
| Check running | Show its start time. | Polling reads the local status and starts no remote work. |
| Unknown host key | Show the presented key's SHA256 fingerprint and ask for the provider's fingerprint. | An exact match is trusted; anything else records nothing ([confirming a fresh host](ssh-connections.md#confirming-a-fresh-saved-address-host)). |
| Changed or revoked host key | Refuse before authentication. | No in-app bypass. |
| Failed or interrupted check | Show the sanitized failure and **Retry connection check**. | The previous snapshot stays, with its collection time and a stale notice. |
| Fresh host or Incomplete foundation | Offer **Set up server**. | Applying needs Shared consent. |
| Target stack | Offer runtimes on Stack and **Create HTTP site** on Sites. | Each change is prepared and reviewed separately. |
| Not manageable | Show the standing and its reasons; keep operating system, capacity and services visible; offer no change controls. | Only a later discovery can change the judgment. |
| Evidence inaccessible or unsupported | Explain what could not be read and keep the evidence under Advanced. | Unknown evidence is never treated as absence. |

Collection time says when observations were read. A successful historical change and current native state answer different questions. A failed refresh never replaces native evidence with local history.

## Site pages

An observed site opens at `/servers/<pk>/sites/<identifier>/overview/`, with **Runtime**, **Database**, **Settings** and **Activity** sections at `/servers/<pk>/sites/<identifier>/<section>/`. A site that discovery sees but that does not follow the target convention has **Advanced** in place of Runtime. The identifier resolves within that registration's last complete observation; the same identifier on another server never shares context.

- **Overview** shows the observed names, account, convention conformity, the HTTPS setting and the certificate state (Issued with its expiry, Waiting, Failing with Caddy's reason, or Renewal due), and collection time. A conforming layout is not called healthy.
- **Runtime** shows the site's PHP and Node selections and prepares a change of either ([runtimes](runtimes.md#site-php-selection)). It distinguishes the current selection, unavailable evidence and an incomplete PHP switch. A plain PHP site also shows its **Readiness path**, `/` by default, and prepares a Site change for another path ([readiness](sites.md#readiness)).
- **Settings** warns that no backup exists before Phase D and prepares a site's removal ([removing a site](sites.md#removing-a-site)). The review lists every deleted resource, and applying needs Destructive consent and the typed primary domain.
- **Activity** lists the reviews and runs recorded for the identifier on this registration, newest first. It is history: an old success, a reused identifier or a site recreated outside Barectl does not establish the current site's identity or health.

While a later connection check is queued, running or failed, site pages keep showing the last successful snapshot with its time and a stale notice, and change controls ask for a fresh observation first. When the last complete observation confirms the site is gone, the page says **Site not found in the latest observation** and offers no change controls. Site pages need `servers.view_server` and `discovery.view_siteobservation`.

A verified site-creation run hands off to the site's page once discovery observes the new site. Until then the run page keeps its own verification and links to the server, so an unobserved site is never presented as current. The run says Barectl checked the site from the server itself; the review warns, without refusing, when a domain does not resolve to the server, because a proxy or CDN is legitimate. Reachability from the internet and application deployment are not verified.

## Review boundaries

Every change goes through the one change engine ([ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md)): prepare, review, apply natively, verify and reconcile.

- Preparing a change reads the server and stores one immutable review with its evidence, effects and consent level. It changes nothing.
- The consent level follows the declared effects. Site changes need Site consent. Server-wide changes, such as Set up server, Add runtime and server defaults, and changes that affect other sites, need Shared consent; a Shared review lists the affected sites, and applying it asks the operator to acknowledge them.
- A review can be applied once, within 15 minutes of preparation. Apply rechecks the reviewed evidence and the affected sites under the native lock and refuses on any difference. An expired or refused review needs a new preparation.
- Navigation never authorizes anything.

## What continues without the controller

Accepted runs are transient systemd units on the server; they finish and leave their evidence without the controller. Everything else needs this controller's worker (`manage.py db_worker`): connection checks, change preparation, **Check outcome** and the discovery after a run.

Barectl's records stay in this controller's database. Another controller with its own database and credentials reconstructs the same server and site pages from native evidence, but its Activity holds none of this controller's runs.

## Recovery

Recovery starts from the original record, never from a repeated submission. [Native recovery](recovery.md) covers the server side.

| Situation | What the page shows | What resolves it |
| --- | --- | --- |
| Unavailable privilege or unreadable evidence | Observations labelled as unknown, not absent; preparation refuses with the privilege it needs. | Grant the access on the server, then refresh or prepare again. |
| Native lock held by another controller | The run stops before any change with the lock conflict. | Wait for the other change, then prepare again. |
| Stale or expired review | The review says it expired. | A new preparation. |
| Site removed outside Barectl | **Site not found in the latest observation**, without change controls; history stays under the identifier's Activity. | Nothing to apply; create the site again if wanted. |
| Failed or interrupted discovery | The previous snapshot, marked stale, with the sanitized failure. | **Retry connection check** after correcting the cause. |
| Partly applied run | The run and the site's Activity name the stage it reached. | A new review, which proposes only what is missing. |
| Incomplete PHP switch | The site's Runtime page names the transition. | A fresh review for the intended runtime, which finishes or reverses it. |
| Lost acknowledgement or unverified outcome | **Outcome not established** with **Check outcome** on the original run. | **Check outcome** inspects the same unit and submits nothing; closing as outcome unknown never records success. |

## Accessibility and verification

Section links use a named navigation region and current-location indication. Routine polls preserve keyboard focus and entered values. State changes update the persistent status announcement; unchanged polls do not repeat it. Narrow layouts keep navigation and action text readable without horizontal scrolling. Direct links, reload and browser history restore the same section; a signed-out restore leads to sign-in. The browser tests check keyboard access, focus, error association, announcements and layout; they are not a full accessibility audit.

## Upstream guidance and project choices

- [USWDS side navigation](https://designsystem.digital.gov/components/side-navigation/) recommends current-page indication and testing the navigation in the application.
- [Django 6.1 authentication and permissions](https://docs.djangoproject.com/en/6.1/topics/auth/default/#the-permission-required-decorator) documents request-level permission checks.
- [Official HTMX 4.0.0 guidance](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-guidance.md) defines explicit inheritance, partial and full request headers, and polling. Barectl keeps the fragment and full-page contract in [frontend assets](frontend-assets.md#htmx-4).

The section map, guidance matrix and authorization boundaries are Barectl decisions. The [workflow competition study](workflow-competition.md) is documentation research, not usability evidence.
