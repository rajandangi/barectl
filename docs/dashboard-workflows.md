# Dashboard workflows

The dashboard organizes work around servers and the sites they host. This document
describes the current operator workflows: the four top-level places, the server and site
pages, creating a site, reviewing a change, following a run, and recovery. It describes
the interface over the change engine; eligibility, consent, the native lock, admission
and verification are unchanged ([changes and jobs](architecture.md#changes-and-jobs),
[ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md)).

## Places

The header leads with **Servers**, **Sites**, **Activity** and **Settings**, and marks
the current place. Each is one activation from any page.

- **Servers** lists saved servers with their connection status. With no servers it asks
  for the first one and offers **Add server**.
- **Sites** lists every observed site across servers and offers **Create site**.
- **Activity** is this controller's record of checks and changes, newest first. It never
  establishes a server's current state.
- **Settings** is installation-wide: the signed-in account and how to change its
  password from the terminal, the controller's approved SSH keys with their public
  halves, how to check that the background worker runs, and the Barectl version with the
  runtimes it offers. Nothing here changes a server.

Opening any page reads stored observations and local records. Only a CSRF-protected POST
queues work, and no page makes an SSH connection.

## Servers

**Add server** saves a connection and queues a connection check
([saved server connections](saved-server-connections.md)). The common form asks for the
name, address, SSH user and key; port and SSH alias sit under **More options**. A new
host's identity is confirmed by pasting the provider's fingerprint
([confirming a fresh host](ssh-connections.md#confirming-a-fresh-saved-address-host)).
Credentials and host trust stay on the controller host; Barectl offers no browser key
upload or host-trust bypass.

A server page opens on **Sites**. Its heading shows the name, the address and one status
line:

| Status | Meaning |
| --- | --- |
| Ready | The last check found the target stack. It does not claim live health. |
| Needs setup | The host is fresh or its foundation is incomplete. |
| Checking… | A connection check is queued or running. |
| Cannot be managed | The last check found a host Barectl will not change. |
| Connection failed | The last check could not connect, or the alias is unusable. |
| Not checked yet | No complete observation exists. |

Below it sits at most one next-action banner, most urgent first: confirm the host's
identity, check the connection, edit an unusable connection, set up the server, or fix
the first finding that needs the operator. The banner's action is a CSRF-protected POST
where it starts a change.

| Section | What it holds |
| --- | --- |
| Sites (default) | Observed sites led by their domains, each opening its site page, and **Create site**. |
| Activity | This server's checks and changes, newest first. |
| Settings | Server-wide choices: **PHP versions** with the sites using each and **Add PHP version**, **Default PHP**, **Default Node.js**, **HTTPS** with the optional certificate contact email, **Database** with the server's MariaDB or PostgreSQL engine and its install or remove review, **Object cache (Valkey)** with the installed version and the one install review, the connection with **Edit connection**, and **Remove server**. |
| Advanced | Host standing and its evidence, the foundation stages, operating system, capacity, components, the web stack and services, the runtime catalog, masters, protections, site pools, the connection record with its host key, discovery history, and **Clean up finished runs**. |

Removing a server deletes its local connection and history from this installation. It
changes nothing on the server.

The old `stack/`, `setup/` and `changes/` URLs redirect to Advanced, the server page and
Activity.

## Sites

A site page opens on **Overview**: its address with an http or https link, its platform,
its PHP version, its status, when it was last checked, and where to upload code (the
site's public folder, as the site user). A WordPress site adds a sign-in link; a Laravel
site its current release and **Deploy**.

| Section | What it holds |
| --- | --- |
| Overview (default) | Address, platform, PHP version, status, last checked time and upload path. |
| Activity | The site's changes, newest first. |
| Database | The site's database binding, or the review that adds one ([databases](databases.md)). |
| Deployments | A Laravel site's releases, **Deploy** and **Roll back** ([deploying](sites.md#deploying-a-laravel-site)). |
| Environment | A Laravel site's environment keys ([settings](settings.md)). |
| WordPress | A WordPress site's constants, password reset and core verification ([WordPress](wordpress.md#actions)). |
| Settings | **PHP version** with **Change PHP version**, **Node.js** with the same choice, PHP settings and the readiness path, domains and HTTPS, and **Remove site**. |
| Logs | Native detail: the site account and paths, its file, missing paths, observed facts, the installed runtime diagnostics, masters, protections and a link to the server's pools. |

A version this server does not have is marked **Installed first**. Choosing it prepares Add
runtime as step one; the run page then offers to continue the switch with the same choice.
The current version is never offered for a change, and a partly applied switch offers both
the target and the current version to finish or reverse it.

A site page shows a stale notice while a later check is queued, running or failed, and
keeps the last successful snapshot. When the last complete observation confirms the site
is gone, the page says **Site not found in the latest observation** and offers no change
controls.

The old `runtime/` and `advanced/` URLs redirect to Settings and Logs.

## Creating a site

**Create site** appears on the Sites page, on a server's Sites section and on a setup
run's success banner. From the global page it first asks which server, listing only Ready
servers and preselecting the only one.

1. **Platform**: PHP, WordPress or Laravel. PHP is selected.
2. **PHP version**: one tile per offered version, labelled by version. The server's
   default is preselected, otherwise the newest installed, otherwise the newest offered.
   A version not on the server says it is installed first and how much it downloads.
3. **Domain**: one field, with **Add another domain** for up to ten.
4. **More options**: the short name, derived from the domain and editable, and the
   Node.js version.
5. **Continue** prepares the change.

When the chosen PHP version is installed, Continue prepares Create site. When it is not,
it prepares Add runtime first; that confirm screen says it is step one of two, and its
successful run offers **Continue to create the site**, which prepares the Create site
review directly with the same answers kept.

Create site's confirm screen says what will happen: a site account, its folders, a
placeholder page, the chosen PHP version and HTTP service. It names any affected sites
and requires the acknowledgement tick box only when the review lists them. On success the
run hands off to the site page once discovery observes the site. The site page then says
where the site answers and, when the server's address is known, where to point DNS. It
never claims the site is public or that an application is deployed.

WordPress and Laravel keep their own forms with their extra fields; the Create site
choice leads to them.

## Reviews and consent

Every change is prepared, reviewed, applied natively, verified and reconciled by the one
change engine. A confirm screen is rendered from the stored review and adds no second
review document or consent level.

- While preparation runs the screen says **Checking the server…** and polls.
- The title and sentences are plain words; the primary action is named for the change and
  **Cancel** returns to where it started.
- A Shared review names the affected sites and requires the existing acknowledgement tick
  box. With no sites affected it says so. A Site review has one button.
- **Show details** is a closed accordion holding the full review: effects, stages, the
  connection and its revision, the admission deadline, digests, consent level, targets,
  kept resources, postconditions and refusals.
- An account without the permission applying needs sees no button and the reason.
- A review that expired or whose connection drifted says **This confirmation is out of
  date.** and offers **Check again**, which prepares a fresh review of the same kind and
  inputs.

## Runs

Every change links to its run. **Progress** is the default tab:

- the plain-words title, the plain steps with the current one marked, polled as the run
  moves, with focus kept;
- the result in one sentence and one next action: **Create site**, **Open the site**,
  **Try again**, **Check what happened**, or **Open the server**.

**Logs** holds the stage names, the systemd unit, invocation, journal lines, consent
level, the original connection and revision, and the audit record. A run continues on
the server if the page or controller disconnects.

## Recovery

Native detail reaches the main path only here, as one sentence and one action.

| Situation | Progress or site page shows | Action |
| --- | --- | --- |
| Lost contact during a run | Barectl lost contact while this was running. It may have changed the server. | **Check what happened** inspects the original run; it starts no new run. |
| No native record remains | The same sentence, with the condition for closing under Logs. | **Close as unknown** with its tick box. |
| Partly applied | This stopped after *plain step*. Nothing after it ran. | **Try again** prepares a fresh review proposing only what is missing. |
| Refused before any change | Nothing changed: *reason*. | **Try again**. |
| Incomplete PHP switch | Changing PHP from 8.4 to 8.5 did not finish. | **Finish the switch** or **Stay on PHP 8.4**, each a fresh review. |
| Out-of-date or expired confirmation | This confirmation is out of date. | **Check again**. |
| Another computer is changing the server | Another computer is changing this server. | **Check again** later. |

Detailed causes, exits and journal lines stay in the run's Logs.

## Activity

**Activity** lists discovery checks and changes across servers, newest first, in plain
words: what was checked or changed, on which server or site, when, and how it ended. Each
row opens its confirm screen or run. Server and site filters narrow the list; a server's
Activity and a site's Activity show the same rows filtered. Activity polls while a row is
active. It is this controller's record and never establishes current state.

## Permissions

Section visibility follows viewing permissions; a hidden control never replaces
authorization on the request. Every mutation is a CSRF-protected POST checked against the
account's permissions. Site pages need `servers.view_server` and
`discovery.view_siteobservation`; editing secrets also needs `operations.manage_secrets`.
Changes need `operations.view_changes`, and applying needs the permissions the review's
consent level declares.
