# Saved server connections

Phase A's Add server journey saves a non-secret connection and explicitly queues read-only discovery. It uses the existing worker, typed SSH target, strict host trust and pyinfra connector. The server remains the authority for readiness and inventory. Connection records belong only to the controller's database.

## Add and check

Enter a display name, an ASCII host name or IPv4/IPv6 address, an SSH user (root by default), and an optional port (22 by default). Use root or an account with passwordless sudo for foundation readiness. Only Ubuntu 26.04 and qualified architectures are eligible for target-stack management. Select this computer's SSH agent; load the authorized key in the agent available to the worker before checking.

Addresses are at most 253 ASCII octets. DNS labels are at most 63 characters and cannot start or end with a hyphen. IPv6 is unbracketed and has no scope. URLs, user@host and embedded ports are refused. SSH users have at most 64 ASCII letters, digits, dots, underscores or hyphens, without a leading hyphen. Ports range from 1 to 65535. Validation and page rendering perform no DNS lookup or SSH. Invalid forms retain valid input.

The advanced SSH alias input resolves supported concrete Host entries into the same typed target. Its captured non-secret endpoint and a digest of resolved authentication and trust settings prevent queued work from following a changed alias. Aliases requiring DNS canonicalization or local FQDN expansion are refused before lookup. Saved addresses do not read authentication settings from SSH configuration.

Save and check commits registration, an immutable connection revision, discovery and its worker task atomically. An identical repeated submission shares the active check. Viewing, reloading or navigating server pages queues nothing. Retry and refresh are explicit actions.

## Authentication and trust

Saved agent mode offers only agent identities. Key-file search and forwarding are disabled, with no fallback to configured or default private-key files. No private key, passphrase, agent identity or arbitrary path is stored in the database or shown as server inventory. Approved key-file references are delivered by the next authentication slice.

`BARECTL_SSH_KNOWN_HOSTS` names the Barectl-owned trust file on the controller, defaulting to `~/.local/share/barectl/known_hosts`. The connector checks it before authentication and creates only its existing private temporary trust copy. Alias mode combines this file with its supported configured trust files; any revoked key is refused across the combined set. This slice never writes trust. Use a pre-trusted host until fingerprint confirmation is delivered by the next trust slice. Unknown identity reports **Server identity not yet trusted**; changed and revoked keys have separate refusals. No accept control exists.

Each computer owns its credentials and trust independently. Saving an endpoint neither authenticates the account nor trusts the host. Removing a registration does not change the server, agent, private keys or trust files.

## Immutable revisions

Every saved definition records mode, address, user, port, alias and revision. Definitions are append-only; queued operations reference the captured row. Discovery rechecks the registration revision and the requesting account's current view, discovery and originating registration permissions before connecting and before publishing. Editing connection details creates a new revision and queues a new check; active remote work blocks retargeting. Existing change preparation, apply and reconciliation use the same captured connection contract.

Registration editing grants no preparation or apply permission. Server viewers see address, user and port. Feature actions still require their own permissions. Historic observations are evidence from the check's original target; they cannot grant authority for an edited target. The remaining whole-workflow provenance and concurrency acceptance is owned by Phase A's revision-admission slice.

## Results

The result records the check time and host standing: Fresh host, Incomplete foundation, Target stack or Not manageable. A Fresh host offers **Set up server** to accounts allowed to change shared resources. Not manageable lists its named reasons. Headroom thresholds remain provisional pending native qualification.

Failures use sanitized messages for identity refusal, unreachable server, rejected authentication and unavailable agent credentials. A check still queued after ten minutes reports that the worker is unavailable for that check, while retaining the queued task for the worker to resume. Raw exception and SSH output never become failure text. A prior success or queued task does not establish live health.

## Verification and upstream reuse

The fast seams are Django form requests, worker publication, recorded host standing and the in-process SSH server through the production connector. The native L0 scenario registers a saved address through the dashboard using a disposable agent and pre-trusted fixture key, then checks readiness. S1 adds fingerprint confirmation when its owning slice lands.

Custom behavior is limited to validated local definitions, revision binding, authorization and operator presentation. Transport, authentication and host-key negotiation remain upstream behavior:

- [Django 6.1 transactions](https://docs.djangoproject.com/en/6.1/topics/db/transactions/): short atomic local writes; no transaction spans network work.
- [pyinfra 3.x SSH connector](https://docs.pyinfra.com/en/3.x/connectors/ssh.html): explicit target and Paramiko connection controls, used with the pinned pyinfra 3.10.0 package.
- [Paramiko 5.0 client](https://docs.paramiko.org/en/5.0/api/client.html): strict host-key verification and agent/file controls.

Phase A starts with fresh controller databases. Fingerprint confirmation, approved file identities and the final revision-admission proof have their own dependent tickets. This document records the registration slice and those boundaries; it does not qualify the whole target stack.
