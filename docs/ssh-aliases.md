# SSH alias registration

Barectl registers a managed server by a display name and an SSH alias configured on the controller host. The dashboard accepts no host names, users, ports, keys, key uploads or commands. Connection settings, credentials and host trust stay in the controller's SSH configuration, agent and key files. Barectl reads the configuration and never writes it, the trust records or key files.

Registration only records the alias. The dashboard labels every registration **Not verified** until a later connection workflow proves it can connect.

## Configuration file

Barectl reads one file: `BARECTL_SSH_CONFIG`, or `~/.ssh/config` of the account running Barectl when that variable is unset. The system-wide `/etc/ssh/ssh_config` is not read, because the planned backend does not read it either. The file is read again on each registration and edit request, so changes on the controller host appear without restarting Barectl.

## Resolution backend

Barectl's planned SSH backend is pyinfra's SSH connector. pyinfra 3.10 reads the configuration file, expands `Include` and strips inline comments itself, then parses the result and looks up each host with paramiko's `SSHConfig` ([pyinfra 3.10.0 `sshuserclient/config.py`](https://github.com/pyinfra-dev/pyinfra/blob/v3.10.0/src/pyinfra/connectors/sshuserclient/config.py), [`client.py`](https://github.com/pyinfra-dev/pyinfra/blob/v3.10.0/src/pyinfra/connectors/sshuserclient/client.py)).

`servers/ssh_config.py` mirrors that pre-processing and uses paramiko 5.0.0 for parsing and lookup ([paramiko configuration API](https://docs.paramiko.org/en/stable/api/config.html)). pyinfra is not installed yet. Its latest release, 3.10.0, requires `paramiko<5`, and paramiko 4.0.0 has an open advisory (PYSEC-2026-2858), which the strict dependency audit rejects. pyinfra's development branch allows paramiko 5 ([pyinfra#1742](https://github.com/pyinfra-dev/pyinfra/issues/1742)). paramiko's `SSHConfig` parsing and lookup code is unchanged between 4.0.0 and 5.0.0. The connection workflow must confirm this equivalence against the pyinfra release it installs, then may replace the pre-processing here with pyinfra's own parser.

This mirroring is a Barectl engineering choice, not a pyinfra or paramiko recommendation.

## Supported

- `Host` entries that name one server, such as `Host web-1` or `Host web-1 web-1.example.com`. Each concrete name is offered as a separate alias. Quoted names are accepted when they contain only letters, digits, `.`, `_` and `-`.
- Settings applied by paramiko's lookup, including `HostName`, `User`, `Port`, `IdentityFile`, `IdentityAgent`, `ProxyJump` and `ProxyCommand`. Barectl does not interpret credentials; it only checks that `Port` resolves to a number from 1 to 65535.
- `Include`, as pyinfra 3.10 processes it. Relative paths are resolved against the including file's directory, `~` is expanded, and glob matches are read in directory order. Missing files are ignored. Including the same file twice is reported as a loop. OpenSSH differs: it resolves relative user includes against `~/.ssh` and sorts glob matches.
- Inline comments that start with `#` after whitespace, outside quotes.

## Not offered

The form lists each skipped Host entry with its reason.

- Patterns containing `*`, `?` or `!` are never offered as servers.
- Names that another entry negates, for example `web` when `Host !web` appears anywhere. paramiko applies a negation only within its own `Host` line, so this rule is deliberately stricter.
- Names that start with `-` or contain spaces, shell characters or other characters outside the accepted set.
- Aliases whose resolved `Port` is not a valid port number.

## Unsupported configuration

These make the whole file unusable for registration. The dashboard explains the problem without repeating the file's contents.

- `Match` blocks. paramiko evaluates `Match` conditions on every lookup, including `Match exec`, which runs a local command. Its host listing also cannot enumerate the servers a `Match` block selects. Barectl rejects the file before any lookup, so no `Match exec` command runs.
- Lines paramiko cannot parse, include loops, missing files, unreadable files and files that are not UTF-8.

## Revalidation and migrated records

The form reads the configuration again when it is submitted. An alias that was removed after the form was shown, a pattern, or any other value outside the current list is rejected. The Servers list flags registered aliases that are no longer usable.

Records created before alias registration keep their old connection details as text for reference only. The migration does not treat them as an alias, even when a Host entry has the same name. These records show **Needs SSH alias** and cannot connect until the operator chooses an alias. Choosing one discards the old details.

Each alias can register one server. The database enforces the unique alias and requires either an alias or migrated details.
