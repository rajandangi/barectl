# Architecture

## Product boundaries

Barectl is one Django application. It may run locally or on a management host. Managed Linux servers remain agentless and expose SSH only for management. Provisioning will install ordinary web-stack packages; agentless does not mean a server can host applications without those packages.

The repository has `config`, `dashboard` (interface integration: Vite assets, sign-in form and HTMX request handling), `servers` (registration, removal and server pages), `discovery` (attempts, snapshots, the worker task and the SSH transport), shared templates, and the Vite frontend sources in `frontend/`. Add domain apps when a workflow needs them. The interface uses USWDS and HTMX 4. `servers/ssh_config.py` reads controller SSH aliases with paramiko, mirroring the planned pyinfra connector's configuration handling (`docs/ssh-aliases.md`). `discovery/ssh.py` is the only remote execution boundary (`docs/ssh-connections.md`). pyinfra is planned for changes to servers. SSH credentials stay in the controller host's agent or key files; hosted credential storage will be designed before team deployments.

## Request and execution flow

Views validate input and authorize access, then call application services. Services create durable jobs. A separate worker process from the same codebase executes infrastructure adapters. Long SSH operations must not run inside HTTP requests.

Discovery follows this flow. `discovery/services.py` owns the discovery attempt lifecycle: every change of an attempt's state applies only while the attempt is still in the expected state. `servers/registration.py` owns registering a server, changing its alias and server removal: `save_server` saves a registration or edit and queues a connection check when the alias is new, and `removal_summary` and `remove_server` remove a server with its discovery history. It reaches attempts only through `queue_discovery`, `recorded_discovery` and `forget_discovery`. Views call those functions and `request_discovery` to check a server again; they turn outcomes into messages and form errors and never change attempts themselves. `servers/discovery_state.py` is the dashboard's one read of discovery: `server_state` for a server's page, with its discovery history, `inventory` for the server list and `activity_rows` for Activity. The page and the list read the controller's alias catalogue too and decide the connection status. Templates never receive attempt rows: each attempt reaches them as an `AttemptView` in the pages' wording, so the server page, its discovery history and Activity describe the same attempt alike, and the polled fragment sends back a token the module issues rather than the stored state. Other modules read attempts only through `discovery/services.py`: `read_discovery` (a server's latest attempt, current snapshot and discovery history in one read), `latest_attempt_statuses`, `history` (every server's attempts for Activity) and `recorded_discovery` each recover abandoned attempts before reading. Queueing records a queued attempt and enqueues the `run_discovery` task in one transaction, using Django's tasks framework with the `django-tasks-db` database backend. `manage.py db_worker` runs the task, which connects with the attempt's alias through `discovery.ssh.connect_alias`, collects observations with `discovery.observations.collect`, the only public collection function, and publishes the snapshot with the attempt's outcome. The `discovery/observations/` package keeps `collect` and the operating system and capacity observations in `__init__.py`, probe reads and the classification of their failures in `probes.py`, packages and service units in `components.py`, the Nginx and PHP-FPM parsers in `parsers.py`, and the Nginx site file and PHP-FPM pool collections in `configuration.py`. `discovery/snapshot.py` owns the snapshot's shape: the observation types the collectors return, `save_snapshot`, `current_snapshot`, and `attempt_snapshots`, which reads attempts with the snapshots they published for the pages. Only that module reads or writes the snapshot tables, which keep typed columns ([ADR 0003](adr/0003-store-discovery-snapshots-in-typed-columns.md)).

Read-only discovery uses paramiko through `discovery/ssh.py`, whose supported configuration, agent and host-trust behavior is recorded in `docs/ssh-connections.md`. pyinfra is planned for changes to servers. Its SSH backend must be tested against the same configuration, agent and hardware-key behavior before promising support. Do not assume every OpenSSH feature works through every transport.

The pyinfra adapter must meet the same host-trust rules as discovery:

- Pass the alias's known_hosts files as `ssh_known_hosts_file` and set `ssh_strict_host_key_checking` to `yes`. pyinfra's default, `accept-new`, adds unknown host keys to known_hosts.
- Refuse the aliases `servers/ssh_config.py` refuses, and resolve them with pyinfra's own `get_ssh_config` so both transports read the same settings.
- Use a pyinfra release that accepts the pinned paramiko version. The dependency audit must still pass. The verification is recorded in [#4](https://github.com/rajandangi/barectl/issues/4#issuecomment-5845273176).

## State and discovery

Store the registration's SSH alias and timestamped observations separately. Connection settings stay in the controller's SSH configuration. The remote server is authoritative for observed configuration. A failed discovery must retain the previous successful snapshot while showing it as stale. Discovery never automatically adopts or rewrites an unmanaged site.

## Trust and credentials

Require authentication, Django permissions, CSRF protection, and verified SSH host identity. The current inventory is shared among permitted operators. It is not a tenant-isolated application.

Credentials start with the controller account's SSH agent or the key files its SSH configuration names. Hosted deployments cannot use a browser user's laptop agent automatically. Any future stored credentials need encryption with the encryption secret outside the database, restricted access, rotation, and log redaction. Never accept arbitrary shell commands from the web interface.

## Changes and jobs

Read-only discovery is the first remote workflow. Later mutations need a reviewed plan, revalidation against current state, per-server serialization, bounded timeouts, audit events, and explicit failure recovery. A plan preview is not a transaction or an automatic rollback guarantee. Validate Nginx/PHP configuration before reload and retain previous configuration for recovery.

Durable jobs use Django's tasks framework with the `django-tasks-db` backend and its `db_worker` command. Per-server serialization is a database constraint on discovery attempts, and apply runs will share it as one table of remote operations ([ADR 0004](adr/0004-serialize-remote-operations-in-one-table.md)). Discovery attempts protect their server from deletion, so removal cannot race an attempt (`docs/ssh-connections.md#server-removal`). SQLite transactions begin immediately, so concurrent requests and the worker wait for each other's writes rather than failing with "database is locked". Attempts interrupted by a forced worker stop, or active for longer than ten minutes, are recovered as interrupted failures, keeping any previous snapshot; finishing filters on still-running attempts so a stale worker cannot overwrite newer results. Queued attempts with a ready task wait for the worker; there is no automatic retry.

## References

- [Django 6.1 release notes](https://docs.djangoproject.com/en/6.1/releases/6.1/)
- [pyinfra documentation](https://docs.pyinfra.com/en/3.x/)
