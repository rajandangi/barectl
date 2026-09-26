# SSH alias registration

Barectl registers a managed server by a display name and an SSH alias configured on the controller host. The dashboard accepts no host names, users, ports, keys, key uploads or commands. Connection settings, credentials and host trust stay in the controller's SSH configuration, agent and key files. Barectl reads the configuration and never writes it, the trust records or key files.

Registering a server, or choosing a new alias for it, queues a connection check. The dashboard shows **Not verified** or the check's progress until the check succeeds. See `docs/ssh-connections.md`.

## Configuration file

Barectl reads one file: `BARECTL_SSH_CONFIG`, or `~/.ssh/config` of the account running Barectl when that variable is unset. The system-wide `/etc/ssh/ssh_config` is not read, because the planned backend does not read it either. The file is read again on each registration and edit request, so changes on the controller host appear without restarting Barectl.

## Resolution backend

Barectl resolves aliases the way pyinfra's SSH connector does. It expands `Include` and strips inline comments as pyinfra 3.10 does ([`sshuserclient/config.py`](https://github.com/pyinfra-dev/pyinfra/blob/v3.10.0/src/pyinfra/connectors/sshuserclient/config.py)), then parses and looks up hosts with paramiko's `SSHConfig` ([configuration API](https://docs.paramiko.org/en/stable/api/config.html)). This is a Barectl choice, not a pyinfra or paramiko recommendation. The dependency decision is recorded in [#3](https://github.com/rajandangi/barectl/issues/3#issuecomment-5843877181).

## Supported

- `Host` entries that name one server, such as `Host web-1` or `Host web-1 web-1.example.com`. Each concrete name is offered as a separate alias. Quoted names are accepted when they contain only letters, digits, `.`, `_` and `-`.
- Settings applied by paramiko's lookup, including `HostName`, `User`, `Port`, `IdentityFile` and `UserKnownHostsFile`. Barectl does not interpret credentials; it only checks that `Port` resolves to a number from 1 to 65535.
- `Include`, as pyinfra 3.10 processes it. Relative paths are resolved against the including file's directory, `~` is expanded, and glob matches are read in directory order. Missing files are ignored. Including the same file twice is reported as a loop. OpenSSH differs: it resolves relative user includes against `~/.ssh` and sorts glob matches.
- Inline comments that start with `#` after whitespace, outside quotes.

## Not offered

The form lists each skipped Host entry with its reason.

- Patterns containing `*`, `?` or `!` are never offered as servers.
- Names that another entry negates, for example `web` when `Host !web` appears anywhere. paramiko applies a negation only within its own `Host` line, so this rule is deliberately stricter.
- Names that start with `-` or contain spaces, shell characters or other characters outside the accepted set.
- Aliases whose resolved `Port` is not a valid port number.
- Aliases that use a setting Barectl's connection does not implement, such as `ProxyJump` or `IdentityAgent`, or a `UserKnownHostsFile` path with `%` tokens. `docs/ssh-connections.md` lists them.

## Unsupported configuration

These make the whole file unusable for registration. The dashboard explains the problem without repeating the file's contents.

- `Match` blocks. paramiko evaluates `Match` conditions on every lookup, including `Match exec`, which runs a local command. Its host listing also cannot enumerate the servers a `Match` block selects. Barectl rejects the file before any lookup, so no `Match exec` command runs.
- Lines paramiko cannot parse, include loops, missing files, unreadable files and files that are not UTF-8.

## Revalidation and migrated records

The form reads the configuration again when it is submitted. An alias that was removed after the form was shown, a pattern, or any other value outside the current list is rejected. The Servers list flags registered aliases that are no longer usable. It resolves only the aliases it shows.

Records created before alias registration keep their old connection details as text for reference only. The migration does not treat them as an alias, even when a Host entry has the same name. These records show **Needs SSH alias** and cannot connect until the operator chooses an alias. Choosing one discards the old details.

Each alias can register one server. The database enforces the unique alias and requires either an alias or migrated details.
