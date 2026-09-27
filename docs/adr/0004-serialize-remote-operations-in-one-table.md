# Serialize remote operations on a server in one table

A managed server runs at most one remote operation at a time, whatever its kind. Discovery attempts are the only kind today; apply runs, which carry out a reviewed configuration plan, are the second. The database enforces the rule with one partial unique index over one table, not with application locking.

When the first apply run is built, the lifecycle columns of `DiscoveryAttempt` become a `RemoteOperation` table: the server (protected from deletion), the SSH alias it connects with, the kind, the status (queued, running, succeeded or failed), its times and the operator-facing failure. Its index allows one queued or running operation per server. Each kind keeps its own data in a table linked one-to-one to its operation: a discovery attempt its host key and the snapshot it published, an apply run its plan and audit events. One lifecycle module queues, claims, advances, recovers and finishes every operation, finds a kind's task records, and runs the kind's own step, so stale recovery and the race rules exist once. Until then discovery attempts keep their own table and index, since a shared table with one kind would be a seam without a second adapter.

Barectl does not give each kind its own table and index. Two indexes cannot stop a discovery attempt and an apply run from running on the same server, and serializing them across tables would move the guarantee from the database into application locks. Barectl also does not mark a server row as busy, because that repeats the operation's status and needs its own recovery.

## Consequences

- A discovery attempt refuses to queue while an apply run on its server is queued or running, and the reverse.
- A server with an active operation of any kind cannot be removed.
- Server removal deletes the server's discovery history. Apply run audit events outlive the server: they record its name and alias rather than depend on the server row.
- Adding a kind of remote operation adds a kind value, its one-to-one table and its step; it adds no lifecycle code or constraint.
