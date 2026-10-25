# Barectl

Barectl lets an operator inspect and manage native Linux web servers from a local or self-hosted application.

## Language

### People and installations

**Operator**:
The person using a Barectl installation to manage its registered servers.
_Avoid_: Customer, tenant

**Barectl account**:
An operator's login to a Barectl installation, local to that installation by default. It is separate from Linux users and does not grant SSH access or server permissions.
_Avoid_: Server user, SSH identity

**Barectl dashboard**:
The operator-facing interface for working with managed servers and discovery results.
_Avoid_: Django admin

**Controller host**:
The machine running Barectl and holding the SSH credentials used to access managed servers. It may be the operator's local computer or a private management host.
_Avoid_: Managed server

**Local database**:
A Barectl installation's default store for its accounts, settings, connection records, queued requests, operation history, and cached server observations. Another authorized device does not need a copy to discover and manage the same server.
_Avoid_: Server source of truth, shared control plane

**Shared database** (planned):
An optional remote application database that operators configure to share Barectl records across local installations. It is not authoritative server state and is not required for independent SSH management.
_Avoid_: Hosted Barectl service, server source of truth

**Discovery worker**:
The separate process from the same application that runs queued remote operations: discovery attempts, change preparations and change runs. Accepted change runs continue on the server without it.
_Avoid_: Agent

### Servers and connections

**Managed server**:
A remote Linux machine registered with Barectl for inspection and management.
_Avoid_: Barectl host, control panel

**Saved server connection**:
A server's non-secret address, SSH username, port and key reference, this computer's SSH agent or an approved key file, saved in immutable local revisions. Each queued operation captures its requested revision. It grants no SSH access or host trust.
_Avoid_: Stored credentials, verified connection

**SSH alias**:
A concrete `Host` name in the controller host's SSH configuration, the advanced way to register a managed server. Its connection settings, credentials and host trust stay in that configuration.
_Avoid_: Connection details, hostname

**Verified connection**:
A connection whose host key matched the controller's trust and whose authentication succeeded, recorded by a succeeded discovery attempt. A registration alone is not verified.
_Avoid_: Connected, online

**Connection status**:
The dashboard's recorded summary of a managed server's connection, with a check timestamp: not verified, connection check queued, checking connection, connection failed, verified, or SSH alias unavailable. Refusals distinguish host identity, reachability, authentication, credential availability and delayed worker dispatch. Verification describes that check, never live health.
_Avoid_: Health, online status

**Server removal**:
Deleting a managed server's registration and its local history from Barectl. Finished change runs are kept as audit without the server. It never connects to the server or changes the controller host, and it waits for any active remote operation.
_Avoid_: Deprovisioning, uninstall

**Supported release**:
The one Ubuntu LTS release Barectl manages, Ubuntu 26.04, on amd64 or arm64, with its own APT, dpkg and systemd series. A server on any other release is Not manageable.
_Avoid_: Supported OS, distribution version

**Database engine**:
The single database server a managed server runs, MariaDB or PostgreSQL and never both, installed from the Ubuntu archive through a reviewed change and hardened to its local socket with no anonymous account or test database. A site's own database and user are separate resources ([databases](docs/databases.md)).
_Avoid_: Database, DB server, MySQL

**Certificate contact email**:
An optional address in Caddy's main configuration that a certificate authority may use to reach the operator. It has one home in Server Settings > HTTPS, is absent by default, and never blocks creating a site ([HTTPS](docs/tls.md#certificate-contact-email)).
_Avoid_: ACME email, admin email, notification email

**Site database**:
A site's own database and its principal, both named `s<id>`, which sign in as the site's Linux user over the local socket — MariaDB `unix_socket` or PostgreSQL `peer` — so no password exists. A plain PHP site adds it from Site Settings > Database through one reviewed change; a Laravel site gets it when the site is created. The principal holds every privilege on that one database and can dump and re-import it ([databases](docs/databases.md#site-databases-implemented-379)).
_Avoid_: Binding, DB user, database account

### Host standing

**Host standing**:
Barectl's judgment of a managed server, made afresh from server evidence on every discovery and review: fresh host, incomplete foundation, target stack or not manageable. Nothing on the server records it.
_Avoid_: Server status, health

**Fresh host**:
A host standing: a supported release and architecture with nothing of the target stack and no other web stack, PHP installation, hosting panel or Nix installation. Only a fresh host or an incomplete foundation can be set up.
_Avoid_: New server, clean install

**Incomplete foundation**:
A host standing: part of the host foundation is present in its supported form and nothing foreign is present, as after an interrupted setup. Setup continues from what exists.
_Avoid_: Broken server, failed bootstrap

**Target stack**:
The one stack Barectl manages, and the host standing of a server whose host foundation is complete in its supported form. Runtimes and sites are added on top of it.
_Avoid_: New stack, profile

**Not manageable**:
A host standing in which Barectl reads the server and shows why, but offers no changes: an unsupported release or architecture, missing privilege, another web stack, PHP installation, panel or Nix installation, or a layout made by an earlier Barectl build. Distinct from the observation outcome Unsupported.
_Avoid_: Unsupported server, legacy server

**Host foundation**:
The server-wide part of the target stack that Set up server installs: the pinned Nix daemon, Caddy and the foundation's tools, and persistent journal storage.
_Avoid_: Bootstrap, base install

**Outside supported settings**:
The state of a target-stack resource that contains a setting Barectl does not interpret. It is reported once, and only the changes that depend on it are blocked; changes within the supported settings are adopted, whoever made them.
_Avoid_: Foreign, unsupported

### Runtimes

**Runtime catalog**:
The pinned set of language runtimes and tools a managed server can install, shared by every site that selects the same entry.
_Avoid_: Package list, per-site toolchain

**Catalog lock**:
The generated list in Barectl's source of every runtime catalog build: for each catalog entry and architecture, the exact Nix store path, version and sizes from one pinned nixpkgs commit, with the builds of earlier commits kept as retired.
_Avoid_: Manifest, package list

**Catalog entry**:
One named runtime or tool in the catalog lock, such as `php84` or `caddy`, with one build per architecture. A retired build is still recognized on a server but never offered.
_Avoid_: Package, attribute

**Runtime**:
A named language branch with a fixed extension set, such as `php84` or `nodejs_24`, installed as a native Nix profile whose store path matches an offered or retired catalog build. Its exact build changes only through reviewed catalog updates. Sites that select the same runtime share its build, never its serving process.
_Avoid_: PHP version, exact build

**Catalog update**:
A reviewed change that replaces an installed catalog entry's build with the one this Barectl release offers. A PHP update moves each site through its private admission drain; the previous generation stays until the new build verifies, then older generations are collected.
_Avoid_: Package upgrade, system update

**Diagnostic master**:
The one `php-fpm@<runtime>` service of an installed PHP runtime, which serves only a private diagnostic pool so Barectl can read the runtime's loaded protections. It serves no site.
_Avoid_: Shared master, PHP service

**Server default**:
The runtime the server's plain `php`, `composer` and `wp`, or `node`, `npm` and `npx`, commands run. Changing it never changes a site.
_Avoid_: System PHP, global version

**Valkey**:
Ubuntu 26.04's Redis-compatible cache server. Barectl installs one package per server, keeps the distribution's shared unit masked, and later gives each site that enables an object cache its own instance. Discovery recognizes it from the package database and systemd alone.
_Avoid_: Redis, cache service

**Object cache**:
A site's use of its own Valkey instance for application caching. Enabling it is a Site change; the server-wide Valkey install is its prerequisite.
_Avoid_: Shared cache, Redis cache

**Object cache instance**:
The packaged `valkey-server@<identifier>` service that runs one site's cache as that site's Linux account, on a private Unix socket with no TCP, password or persistence, a reviewed memory limit and `allkeys-lru`. It stays outside the site's automation slice, and removing the site removes it.
_Avoid_: Cache server, Redis instance

### Sites

**Site**:
A PHP application with its own Linux site user, directory, site master, private admission and Caddy site file, following the site convention. Discovery recognizes a site from native evidence, whoever made it.
_Avoid_: Website, domain, vhost

**Site identifier**:
The permanent 3 to 24 character name that names a site's accounts, directory, services and files.
_Avoid_: Site name, slug

**Site user**:
The dedicated Linux identity under which one site's PHP application runs. It is separate from the operator's Barectl account and SSH identity.
_Avoid_: Operator, SSH user

**Site convention**:
The one native layout Barectl creates and recognizes for a site: its paths, owners, modes, accounts, services and configuration, with bounded supported settings. A site that matches it was read that way; this is neither a serving check nor permission to change it.
_Avoid_: Template, healthy site

**Site master**:
A site's own PHP-FPM service for one runtime, running its pool as the site user. A site has one, or two during a PHP switch.
_Avoid_: Pool, shared master

**Private admission**:
A site's own HAProxy process, which receives the site's PHP requests from Caddy and decides which site master serves them. It lets a PHP switch drain the old master before stopping it.
_Avoid_: Load balancer, proxy

**PHP switch**:
A reviewed change of a site's runtime that starts the target site master, moves admission to it, and stops the source only after its work has drained.
_Avoid_: PHP upgrade, restart

**Incomplete transition**:
A PHP switch that stopped before the source master was drained and stopped, reconstructed from native evidence. A fresh review finishes or reverses it.
_Avoid_: Failed switch, broken site

**Deploy key**:
An ed25519 key pair a Laravel site generates on the server as the site user, in the site's private area, so an SSH repository can be read without a credential leaving the server. Only its public half is shown, and a deploy never rotates it (Phase B #382, [creating a Laravel site](docs/sites.md#creating-a-laravel-site)).
_Avoid_: SSH key, repository key

**Readiness path**:
The application path Barectl requests with a site's primary Host after a change, `/` by default. At `/` an answer below a server error passes; at another path it must be exactly 200. A custom path is native evidence in the site's Caddy file, not a Barectl marker ([readiness](docs/sites.md#readiness)).
_Avoid_: Health endpoint, healthcheck URL

**Log read**:
One explicit, Read-consent remote operation that returns a bounded, scrubbed page of one named site log. It occupies the server's operation slot and stores its page only on its own row. Opening the Logs section is not a log read.
_Avoid_: Log fetch, tail, download

**Log page**:
The typed evidence of one log read: at most 500 lines and 256 KiB of text, a cursor for older lines, a cursor for the next live line when the source is a journal, and the names of the files or units it came from. It is deleted after 24 hours or at the next read of that log.
_Avoid_: Log file, cached log

**Live view**:
A journal log's open panel that asks for lines after its newest cursor while the page is visible, and stops asking while the page is hidden or closed. It appends lines without moving focus and announces each batch through the Logs status region. It is operator reading, not monitoring.
_Avoid_: Log streaming, tail -f, real-time monitoring

**Log rotation**:
The root-owned `/etc/logrotate.d/barectl-site-<identifier>` file that rotates the logs Barectl creates in a site's log directory daily or at 20 MiB, keeping five compressed files for 14 days. Caddy and Laravel rotate their own logs.
_Avoid_: Log cleanup, truncation

**Site observation**:
The observation of one site in a discovery snapshot, carrying exactly one state: managed, partly applied, or not following the convention. Only accounts allowed to view site observations see them.
_Avoid_: Site health, managed site

**Not following the convention**:
The state of a site resource that differs from the site convention or holds a setting outside the supported ones. The observation names it, and only the changes that depend on it are blocked.
_Avoid_: Foreign site, custom site

**Partly applied**:
The state of a site, or the execution outcome of a run, where some convention resources exist and match while others are absent. A new review creates only what is missing and never replaces what exists.
_Avoid_: Rolled back, failed without changes

### Discovery

**Discovery**:
A read-only inspection of a managed server's current configuration and resources.
_Avoid_: Provisioning, bootstrap

**Reconstruction**:
Rebuilding supported server views from native configuration, service state, and available logs in a fresh Barectl installation without the previous installation's database. It cannot recover another device's private application records or native history the server no longer retains.
_Avoid_: Database restore, provisioning

**Discovery attempt**:
One queued run of connection verification and discovery for a managed server, with the outcome queued, running, succeeded or failed. It shares the server's one active slot with other remote operations.
_Avoid_: Job, scan

**Discovery snapshot**:
The timestamped observations from a discovery run, including warnings about anything that could not be inspected. A snapshot describes what was observed at collection time, not the server's live state.
_Avoid_: Live monitoring, real-time status

**Stale observation**:
The last successful discovery snapshot while a later discovery attempt is queued or running, or after it failed. Pages keep showing it with its collection time and a notice, but it cannot authorize a change until a new attempt succeeds.
_Avoid_: Cached state, current observation

**Discovery history**:
The attempts recorded in this Barectl installation for one managed server, newest first. It is not reconstructed from the server's logs or another device's private database.
_Avoid_: Attempt log

**Observation**:
One fact about a managed server recorded in a discovery snapshot, together with its observation outcome, the commands or files it was read from, and any warning.
_Avoid_: Result, check

**Observation outcome**:
Whether an observation produced a finding: observed, absent, inaccessible or unsupported. Absent is a positive finding that something does not exist; unsupported is no finding at all.
_Avoid_: Status (in prose), error

**Observed**:
The observation outcome when Barectl read the fact and interpreted it.

**Absent**:
The observation outcome when Barectl's supported way of inspecting worked and showed that the thing does not exist on the managed server. A missing inspection tool never makes something absent.
_Avoid_: Missing, not found

**Inaccessible**:
The observation outcome when the SSH user's permissions refused the read. Ordinary discovery never escalates privileges to overcome it.
_Avoid_: Forbidden, denied

**Unsupported**:
The observation outcome when Barectl reached no conclusion, because what it read is not in a form it interprets or its way of inspecting is unavailable on the server. It says nothing about whether the thing exists.
_Avoid_: Unknown, failed

**Web-stack component**:
One of the distribution web-stack products discovery looks for in the dpkg database: Nginx, PHP-FPM, MariaDB, PostgreSQL or Certbot. None is part of the target stack.
_Avoid_: Service, software, stack

**Component observation**:
The observation of one web-stack component in a discovery snapshot: its package observation and its service observation, each with its own observation outcome.
_Avoid_: Service observation, service

**Package observation**:
The half of a component observation that records which of the component's packages are installed and their versions.
_Avoid_: Version check

**Service observation**:
The half of a component observation that records the service states of the component's service units.
_Avoid_: Service status, health check

**Service unit**:
A systemd unit that runs part of a component or site, such as `caddy.service`.
_Avoid_: Service, daemon

**Service state**:
The running state systemd reports for a service unit, such as active (running) or inactive (dead).
_Avoid_: Service status, health

### Changes

**Remote operation**:
One queued run that connects to a managed server: a discovery attempt, a change preparation or a change run. Its lifecycle states are queued, running, reconciling, succeeded and failed. Within one Barectl database, a server has at most one queued, running or reconciling remote operation; independent devices coordinate through the mutation lock.
_Avoid_: Job, task

**Change kind**:
A registered type of server change that supplies the engine's inspection, pure review, native body and verification. It does not choose the consent level the change needs.
_Avoid_: Feature-specific apply engine

**Change preparation**:
A remote operation that reads a server, with root or verified noninteractive sudo where the kind needs it, to build one review. It changes nothing and cannot authorize the change.
_Avoid_: Plan, dry run

**Review**:
The one local, immutable record of the evidence, declared effects, derived consent and versioned kind-specific document approved for a possible change, or the reasons it is refused. A run references the review it applies.
_Avoid_: Plan copy, run-side review

**Consent level**:
The permission scope derived from a review's declared effects: Read, Site, Shared or Destructive.
_Avoid_: Feature permission

**Affected site**:
A site other than the target whose service a Shared review's effects reach. The review lists it, applying asks the operator to acknowledge it, and the list is rechecked under the mutation lock.
_Avoid_: Neighbour, collateral

**Refusal**:
One reason a review cannot be applied, with what ordinary administration resolves it. A refused review is still a record; Barectl changes nothing.
_Avoid_: Error, failure

**Admission deadline**:
The time on a managed server's monotonic clock, 15 minutes after a review's evidence was collected in the same boot, after which the review can no longer be applied. It limits admission, not the lifetime of accepted work.
_Avoid_: Expiry date, timeout

**Change run**:
A remote operation that submits one review's native body to a managed server as a transient systemd unit and closes from native evidence of it. Its approval and audit records belong to the Barectl installation and outlive the server's registration.
_Avoid_: Deployment, provisioning run

**Execution outcome**:
What native evidence established about a change run: succeeded, refused before changes, partly applied, failed or timed out. Separate from verification and from the run's lifecycle state.
_Avoid_: Result, status

**Verification outcome**:
Whether a review's postconditions held when checked with fresh reads after a successful execution, or why they could not be checked.
_Avoid_: Health check

**Reconciliation**:
Establishing a change run's execution outcome from native evidence of its own transient unit and journal after an interruption or uncertain response, through Check outcome. A reconciling run keeps the server's active slot and is never submitted again.
_Avoid_: Retry, replay, rollback

**Outcome unknown**:
A change run whose native evidence is gone, so Barectl cannot establish whether its changes completed. It closes as failed with outcome unknown only after an operator acknowledges it and Barectl proves, under the mutation lock, that the run can no longer start or still be running.
_Avoid_: Failed without changes, succeeded, safe to retry

**Mutation lock**:
The one empty, root-owned lock file, `/run/lock/barectl/mutation.lock`, that every change run takes without waiting before it checks its boot, deadline and evidence. It excludes changes from every controller of a server, which a local database cannot. It holds no data.
_Avoid_: Lease, lock record

**Confidential input**:
A secret value typed in an authenticated dashboard request, sealed with the worker's key and stored only as ciphertext in its run, then delivered to the managed server as standard input to a root-only tmpfs file that the transient unit consumes and removes on every exit path. It is write-only, never appears in commands, unit properties, the journal, records or responses, is cleared once sent, and cannot be read after a worker restart or 10 minutes ([ADR 0032](docs/adr/0032-keep-secrets-in-private-native-files.md)).
_Avoid_: Password field, stored credential, environment variable

**Manage secrets**:
The permission, separate from a change's consent permission, that applying a change which writes a confidential input also requires. It is rechecked when the change is prepared, queued and applied, so site operators can be denied access to secrets without denying every change.
_Avoid_: Admin, owner

**Cleanup of finished runs**:
A reviewed change that makes systemd forget retained, finished Barectl units after rechecking each one under the mutation lock. It never stops a unit with processes, keeps journal entries and Barectl's audit, and can leave another installation's run as outcome unknown.
_Avoid_: Garbage collection, reset

**Activity**:
The recorded discovery attempts, reviews and change runs across managed servers, newest first. A server's Activity shows those of its registration, and a site's Activity those recorded for its identifier; neither establishes a current resource's identity or state.
_Avoid_: Logs, event feed

**Native server history** (planned):
Past activity evidenced by logs and records that the server's operating system and services retain. It may be incomplete or unavailable and does not include private Barectl operation records.
_Avoid_: Discovery history, complete audit trail

**Jobs view** (planned):
A managed server's dashboard section for supported running work, schedules, background services and retained native server history. It is distinct from Activity's private Barectl records and does not list individual application queue items.
_Avoid_: Activity, complete audit trail, application job history

**Automation slice**:
The root-owned systemd slice `barectl-site-<id>.slice` that holds one site's scheduled tasks and queue workers and nothing else. Stopping it never stops the site's web serving ([ADR 0036](docs/adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md)).
_Avoid_: Service group, worker pool

**Scheduled task**:
One reviewed, native timer and bounded service that runs a site's application work on the server under the site's own account, with no Barectl controller involved. WordPress server cron is the first one ([automation](docs/automation.md)).
_Avoid_: Cron job, background process

**Server cron**:
A WordPress site's scheduled events run every minute by the managed server instead of by page loads. Barectl sets the site's `DISABLE_WP_CRON` only after one server run has succeeded and clears it before the server task stops.
_Avoid_: WP-Cron, system cron

**Skipped tick**:
A calendar elapse that did not start a run because the previous run of the same scheduled task was still active, inferred from the run's native start and end timestamps. It is shown as skipped, never as success.
_Avoid_: Dropped run, missed cron

**Fence**:
The step that stops a site's automation slice, keeps it from starting, and proves the slice has no processes before a change to that site's code, schema, runtime or settings proceeds; its restore starts exactly the work the review declared ([automation](docs/automation.md#fencing-later-changes)).
_Avoid_: Pause, maintenance mode

### Later phases

Terms for planned WordPress and Laravel sites, site automation and backups are defined in the Phase B ([#356](https://github.com/rajandangi/barectl/issues/356)), Phase C ([#357](https://github.com/rajandangi/barectl/issues/357)) and Phase D ([#358](https://github.com/rajandangi/barectl/issues/358)) specifications.

**Security review** (planned):
A server's plain-language findings about its firewall, SSH sign-in, automatic security updates, pending updates and restart requirement, reconstructed from native evidence with its collection time. It reports what Barectl could read; it is not a score or a statement that the server is secure.
_Avoid_: Security score, audit, compliance check

**Security finding** (planned):
One observed fact in a security review with its impact and the reviewed action or ordinary administration that addresses it. Unreadable evidence is an unknown finding, never a passing one.
_Avoid_: Vulnerability, alert

**Firewall standard** (planned):
UFW active with IPv6, default deny incoming, allow outgoing and deny routed, allowing each effective SSH port, HTTP and HTTPS, plus operator port rules from anywhere or one network. Any other rule or packet-filter manager does not follow the standard.
_Avoid_: Security group, cloud firewall

**SSH sign-in policy** (planned):
The fixed sshd drop-in that requires key sign-in and limits root to keys, or refuses root when Barectl does not connect as root. The effective `sshd -T` result decides whether it holds.
_Avoid_: SSH hardening, key management

**Confirm-or-revert window** (planned):
The fixed period after a firewall or SSH change during which a transient systemd timer restores the recovery preimage unless a new verified connection from the controller confirms access. Other Barectl mutations refuse while it is open.
_Avoid_: Rollback, grace period

**Automatic security updates** (planned):
Ubuntu's standard unattended-upgrades configuration: daily list refresh and unattended installation from the distribution's allowed origins, without automatic reboot. Barectl enables it but never runs it.
_Avoid_: Auto-patching, Barectl updates

**Pending update** (planned):
An installed package with a newer candidate in the server's current package lists, marked as security, other, phased, held or blocked. The list is only as current as its last refresh.
_Avoid_: Available upgrade, outdated package

**Restart required** (planned):
Ubuntu's `/run/reboot-required` evidence that installed packages take effect only after a reboot, with the packages that requested it.
_Avoid_: Reboot pending, unhealthy server
