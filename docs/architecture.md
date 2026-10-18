# Architecture

## Product boundaries

Barectl is one Django application. It may run locally or on a management host. Managed Linux servers remain agentless and expose SSH only for management. Barectl sets up ordinary native software on them, Caddy, Nix-supplied runtimes, HAProxy and PHP-FPM ([target architecture](target-architecture.md)); agentless does not mean a server can host applications without that software.

The [core philosophy](../README.md#core-philosophy) governs discovery and management. Managed servers must remain independently operable if Barectl and its local database disappear. A persistent controller or external control-plane service must not be required for applications to keep running or for an operator to manage the server through ordinary Linux tools ([native recovery](recovery.md)).

The interface uses USWDS and HTMX 4. `discovery/ssh.py` is the only remote execution boundary ([SSH connections](ssh-connections.md)); preparation and apply use the same `RemoteShell` it opens. SSH credentials stay in the controller host's agent or key files.

## Module map

One Django monolith. `config/` holds settings, URLs and the worker configuration; each domain is an app. Find behavior by app, then by the module role.

| App | Owns |
| --- | --- |
| `dashboard/` | Interface integration: Vite assets, sign-in, HTMX request handling, and shared browser test support (`browser_testing.py`, `testing.py`). |
| `servers/` | Server registration and immutable connection rows (`models.py`), revision-bound saves and local removal (`registration.py`), typed connection targets (`connections.py`), approved controller key references (`credentials.py`), fingerprint confirmation (`trust.py`), SSH alias resolution (`ssh_config.py`, `aliases.py`), the server pages (`views.py`), the dashboard's discovery reads (`discovery_state.py`) and Overview's Needs attention list (`attention.py`). |
| `operations/` | The shared remote-operation lifecycle and worker task (`lifecycle.py`, `tasks.py`); the change engine (`engine.py`, `services.py`), its four-member kind seam and effect-derived consent (`consent.py`), validated preparation inputs (`inputs.py`), the review and run pages (`views.py`, `presentation.py`); the native adapter (`native.py`) and package-maintenance admission (`apt.py`); and the cleanup kind (`cleanup.py`). |
| `discovery/` | Read-only attempts, snapshots and the SSH connection. `ssh.py` is the only remote execution boundary; `observations/` collects the operating system, capacity, components and host standing, and calls the runtime and site readers on a Target stack host. `root_read.py` runs fixed reads with verified root or sudo. `snapshot.py` owns the snapshot tables, `presentation.py` words observations, and `recorded.py` records and replays real command output for the fast tests ([recorded transcripts](quality.md#recorded-transcripts)). |
| `bootstrap/` | Host standing (`standing.py`), the setup journey (`foundation_setup.py`) and the host foundation kind (`foundation.py`), with checked-in fixed reads and the mutation body in `bodies/`. |
| `runtimes/` | The runtime catalog lock (`catalog_lock.json`, generated from `catalog_pins.json` by `lock_generation.py` where Nix is installed) and its validated reader (`catalog.py`); the Add runtime kind (`change.py`), the diagnostic master convention (`configuration.py`), runtime reconstruction and live protections (`observation.py`, `live.py`, `bodies/`), server command defaults (`defaults.py`, `defaults_forms.py`, `defaults_views.py`), and the Stack page wording (`presentation.py`). |
| `sites/` | Site names (`names.py`), configuration (`configuration.py`) and private HAProxy and per-site FPM rendering (`serving.py`); the Create HTTP site kind (`change.py`, `forms.py`, `views.py`); reconstruction (`observation.py`, `recognition.py`); PHP selection (`php_change.py`, `php_forms.py`, `php_views.py`) and Node selection (`node_change.py`, `node_views.py`). `bodies/` holds the native bodies: `common.py` creates and verifies sites, `admission.py` binds HAProxy configuration, process, API and state, `site_fpm.py` verifies a loaded master, and `php_runtime.py` owns selection, drain, finish and reverse. |
| `databases/` | Database-engine recognition (`observation.py`), the Install and Remove database engine kinds (`engine.py`), the reduced exact APT transaction (`packages.py`) and its staged body (`bodies/install.sh`, `bodies/remove.sh`), and the Server Settings > Database wording (`presentation.py`, `views.py`) ([databases](databases.md)). |
| `frontend/`, `templates/`, `static/` | Vite/TypeScript/Sass sources, Django templates, and checked-in static assets. |
| `disposable/`, `docker/disposable-server/` | The native harness: `run-scenarios.sh`, `mirror.sh`, `build.sh`, and `disposable/scenarios.py`, `mirror.py`, `images.py`, `machine.py`, `quarantine.py` and `native_mirror/`, with the scenarios as `disposable/test_*.py` ([native layer](quality.md#native-layer)). |

Module names repeat across apps with the same role. Read the name as the role, not the app:

- `views.py` validates input and authorizes, then calls a service; it holds no remote work.
- `services.py` is the application service a view calls, and queues durable jobs.
- `models.py` and `migrations/` hold the app's typed rows.
- `change.py` is a change kind: inspection, pure review, native body and verification. `bodies/` holds the fixed native reads and bodies it stages.
- `presentation.py` words stored rows for templates.
- `fakes.py` is the app's in-memory fake remote for unit tests; `*_testing.py` is test support shared across test modules (tests never import other test modules).
- `test_*.py` are Django tests.

## Request and execution flow

Views validate input and authorize access, then call application services. Services create durable jobs. A separate worker process from the same codebase executes infrastructure adapters. Long SSH operations never run inside HTTP requests.

`operations/lifecycle.py` owns every remote operation's lifecycle ([ADR 0004](adr/0004-serialize-remote-operations-in-one-table.md)): queueing with its worker task in one transaction, claiming, conditional transitions that apply only while the operation is still in the expected state, the one active operation per server, and recovery of abandoned operations for kinds that allow it. The kinds are discovery attempts, change preparations and change runs. Queueing uses Django's tasks framework with the `django-tasks-db` database backend, and `manage.py db_worker` runs the task.

Discovery: `servers/registration.py` saves a registration or edit and queues a connection check when the connection changes, and removes a server with its local history. It reaches attempts only through `discovery/services.py`, whose public functions recover abandoned attempts first. `servers/discovery_state.py` is the dashboard's one read of discovery; templates never receive attempt rows. The discovery step connects with the attempt's captured connection through `discovery/ssh.py`, collects observations with `discovery.observations.collect`, and publishes the snapshot with the attempt's outcome. Only `discovery/snapshot.py` reads or writes the snapshot tables, which keep typed columns ([ADR 0003](adr/0003-store-discovery-snapshots-in-typed-columns.md)). `discovery/presentation.py` names each observation once for the operator.

Changes: the change engine is the one change boundary ([ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md)). `operations/engine.py` owns preparation, immutable reviews, apply submission, verification and reconciliation. A `ChangeKind` supplies inspection, a pure review, a staged native body and verification; each app registers its kinds in its `AppConfig`. The engine derives consent from declared effects, stores affected sites with Shared reviews and places their digest check under the native mutation lock. A run references its review with `PROTECT`; it does not copy review fields. Scope permissions are declared on the review model. `operations/native.py` builds the `systemd-run` submission, inspection and lock probe ([ADR 0006](adr/0006-use-native-bootstrap-execution.md)). After a verified run that changes what discovery reads, the engine queues discovery bound to the applying account and the original connection.

Read-only discovery, preparation and apply connect through pyinfra's SSH connector in `discovery/ssh.py`. pyinfra provides SSH transport and execution only; it does not provide durable remote jobs or coordination across devices.

The pyinfra connection follows these rules:

- Barectl captures an immutable non-secret connection definition when queueing. Saved addresses use the worker's SSH agent with key search and forwarding disabled. Advanced aliases resolve through `servers/ssh_config.py`; a captured digest refuses changed alias target or credential/trust settings before dispatch. pyinfra does not read the controller's SSH configuration.
- Host keys are checked with `ssh_strict_host_key_checking` set to `yes` against a private copy of the selected trust entries without revoked keys. Saved addresses use the controller-owned file named by `BARECTL_SSH_KNOWN_HOSTS`; alias mode combines it with supported configured trust files. `servers/trust.py` confirms a captured unknown saved-host key against the provider fingerprint and atomically updates only the owned file under a controller file lock. pyinfra's default, `accept-new`, adds unknown host keys to known_hosts.
- Collectors keep `RemoteShell` and its numeric exit status, output and truncation flag. The connection recovers them from a fixed shell wrapper; it does not use pyinfra facts or operations for discovery.
- There is one execution backend. It uses pyinfra's documented connector data, including `ssh_paramiko_connect_kwargs`, and paramiko's documented `sock` and `transport_factory` connection arguments.

## State and discovery

Store non-secret saved connection definitions and timestamped observations separately. [Saved server connections](saved-server-connections.md) hold an address, SSH user, port and either this computer's SSH agent or an approved key file, with immutable revisions captured by queued operations. Discovery rechecks the current revision and the view, discovery and originating registration permissions before dispatch and publication. An advanced alias uses the same typed target boundary. Fingerprint confirmation and approved key files use the same captured connection. Inventory and review admission are bound to the captured connection; older observations stay labelled as history of their original target, conflicting edit forms are rejected, and reconciliation and retained audit keep their original targets. The server is authoritative for observed configuration. A failed discovery retains prior evidence only for its original target; observations from an earlier connection revision cannot authorize an edited target. Discovery never rewrites a site.

A fresh controller with authorized SSH access must be able to reconstruct supported observed state without importing the previous controller's database. Each device maintains a local database by default for its Barectl login, preferences, saved connections, queued requests, operation history, and cached observations. The local Barectl login controls access to that application; SSH access and server permissions determine what it can inspect or change remotely. Connection definitions are stored locally; private keys stay on the controller host. Configuration must remain inspectable through ordinary server tools, and incomplete observations must remain explicit.

Cached observations speed up the dashboard but cannot establish current server permissions, remote job status, or configuration when native evidence is unavailable. Mark their freshness and verification limits explicitly. Native logs and service state may explain past activity, but discovery cannot recover native history that was never recorded or is no longer retained. Barectl must not create its own server-side tracking files, inventory manifests, audit journals, or management database to fill that gap. Normal service configuration and native execution or coordination facilities remain allowed; discovery itself stays read-only.

Barectl's own operation records stay in its application database. Another independent installation cannot reconstruct those records through discovery, though it can inspect available native server history and current state. A local queued request is not evidence that a server accepted or executed it, and losing local state must not trigger blind replay. Store cached observations in typed columns as defined in [ADR 0003](adr/0003-store-discovery-snapshots-in-typed-columns.md).

### Management from multiple devices

Multiple local Barectl installations must be able to manage the same server independently, without requiring a shared database, synchronization, or a hosted Barectl service. Each device establishes its own authorized SSH access and host trust. Its discovery cycles refresh its local view from the server, including changes made by another device or ordinary administration tools.

Mutations must revalidate server state and coordinate conflicting operations across devices using native Linux facilities or established, widely used packages verified against upstream guidance. A lock or queued job in one device's database cannot provide that guarantee. [ADR 0004](adr/0004-serialize-remote-operations-in-one-table.md) covers serialization within one application database; additional coordination must satisfy these requirements without a persistent Barectl agent, central service, or custom server-side tracking records. Every change uses a detached transient systemd service and one native nonblocking mutation lock, with boot and deadline fencing and native reconciliation ([ADR 0006](adr/0006-use-native-bootstrap-execution.md)). The native S10 scenario submits from two controllers with independent databases and keys together: one change runs, and the other refuses without waiting and needs a new review. The local database constraint is never presented as that exclusion.

When a conflicting operation is active, show the available native evidence and block the requested change. After it finishes, rediscover and require a new operator review instead of automatically applying a queued stale plan. Another device may detect an active operation without knowing its detailed Barectl history. If reliable coordination cannot be established, refuse the conflicting change; do not claim concurrent execution is safe.

Acceptance must cover two controllers with independent databases: a change from one is discovered by the other, conflicting changes are prevented or explicitly rejected, and an interrupted operation is reconciled against server evidence. Either controller must remain usable when the other controller and its database are unavailable.

### Optional shared database

Operators may choose a remote database to share Barectl application records across local installations. This is planned support, not a requirement for connecting to or managing a server. It does not require hosting the Barectl application, and shared records do not override native server state. An independently configured local installation must still be able to connect through SSH if the shared database is unavailable; automatic offline failover is not promised.

Barectl uses local SQLite. Shared database support needs explicit design and testing for account access, connection references, worker ownership, and concurrent records. A shared database alone does not make one device's SSH agent or key files available on another, and it cannot coordinate an independent controller that uses a different database.

### Standard configuration and reconstruction

Provisioning uses one documented configuration convention for each supported distribution and stack. Choose concrete paths, naming rules, and service configuration from version-matched distribution and upstream guidance before implementing them. These conventions must use ordinary Linux configuration and remain understandable with standard administration tools.

Discovery must reconstruct resources and their relationships from current server evidence. Barectl recognizes its own convention rather than interpreting arbitrary layouts: a resource is managed when its native evidence matches the convention within the supported settings, whoever made it, and a setting Barectl does not interpret is reported once as Outside supported settings, blocking only the changes that depend on it ([ADR 0015](adr/0015-recognize-only-the-convention.md), [ADR 0026](adr/0026-manage-fresh-hosts-on-one-target-stack.md)). A host with another web stack is Not manageable as a whole. Discovery does not follow arbitrary includes or derive roots or sockets from foreign configuration. A naming convention can help locate resources, but names alone must not establish ownership or relationships. Conflicting evidence must produce an explicit unresolved relationship rather than a guess.

Every cycle must reread the supported configuration, recognize external additions, changes, and removals, and avoid retaining an old relationship as current when inspection can no longer verify it. A previous snapshot may support comparison and history; it must not be required for reconstruction. Discovery stays read-only and must not rewrite an existing server to match Barectl's provisioning conventions.

Each provisioning feature includes a reconstruction acceptance test: configure a disposable server, connect from a separate controller with a fresh application database, and reconstruct the resources and relationships that feature created. Repeat after an external configuration change. Reconstruction must not require importing the first controller's records or reading custom Barectl tracking records from the server.

For server user, native history, and job views, verify reconstruction from retained native evidence and explicit unavailability when it cannot be read or no longer exists. A stale local copy must never be promoted to authoritative state because verification failed. Tests must not rely on custom Barectl records written to the server or promise recovery of another device's private operation history.

## Trust and credentials

Require authentication, Django permissions, CSRF protection, and verified SSH host identity. The current inventory is shared among permitted operators. It is not a tenant-isolated application.

Saved connections choose the controller account's SSH agent or an approved key-file reference. Advanced aliases use the key files and agent from their supported SSH configuration. Hosted deployments cannot use a browser user's laptop agent automatically. Any future stored credentials need encryption with the encryption secret outside the database, restricted access, rotation, and log redaction. Never accept arbitrary shell commands from the web interface.

## Changes and jobs

Every change has a reviewed plan, revalidation against current state under the native lock, coordination across controllers, bounded timeouts, records in the Barectl application database, and explicit failure recovery. A review is not a transaction or an automatic rollback guarantee. Configuration is validated before a reload, and a failed Caddy reload restores the previous files.

Accepted changes run as transient systemd services under the native lock ([ADR 0006](adr/0006-use-native-bootstrap-execution.md)) and continue when the initiating device disconnects; Barectl inspects their native status on reconnection. General scheduling is later work ([ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md)). This does not permit a Barectl agent or a custom operation journal on the server. Requests that never reached the server remain local and unexecuted; an uncertain outcome is verified, never blindly retried.

Discovery attempts and change preparations run in the controller's `db_worker` and do not continue after that controller stops. Per-server serialization within this application database is one constraint on the table of remote operations ([ADR 0004](adr/0004-serialize-remote-operations-in-one-table.md)), with the native lock coordinating independent databases. Remote operations protect their server from deletion, so removal cannot race an attempt ([server removal](ssh-connections.md#server-removal)). SQLite transactions begin immediately, so concurrent requests and the worker wait for each other's writes rather than failing with "database is locked"; the write-ahead log keeps a request's reads from waiting behind those writes, and the busy timeout outlasts any single worker transaction. Attempts and preparations interrupted by a forced worker stop, or active for longer than ten minutes, are recovered as interrupted failures, keeping any previous snapshot. A change run is recovered the same way only until it is dispatched; afterwards an interruption leaves it reconciling, and it is never submitted again.

The only Barectl-specific object on the server outside native configuration is the empty, root-controlled lock file. It holds no inventory, PID, lease, review or history. Transient units and retained journals are read as native evidence; approval and audit records stay local.

## Later phases

The [target architecture](target-architecture.md) records the accepted direction for databases, HTTPS, WordPress and Laravel (Phase B), automation and object cache (Phase C), backups (Phase D) and operations (Phase E). Later phases add their own apps on the same change engine, native adapter and SSH boundary.

## References

- [Django 6.1 release notes](https://docs.djangoproject.com/en/6.1/releases/6.1/)
- [pyinfra documentation](https://docs.pyinfra.com/en/3.x/)
