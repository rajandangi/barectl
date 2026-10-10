# Install site certificates with one operator action

> Superseded for new servers by [ADR 0027](0027-serve-sites-and-https-with-caddy.md): Caddy owns issuance and renewal.

Accepted for v0.3. This changes the TLS operator interaction in the original v0.3 specification and extends ADR 0009 for certificate installation. Site creation and the advanced plan actions retain their explicit reviews.

## Decision

A site offers **Create and Install** with its discovered domain names and a contact email. That click authorizes the fixed certificate installation goal, including the authority's subscriber agreement. There is no separate agreement checkbox or intermediate approval. Certbot's existing `--agree-tos` handling registers the account noninteractively. Staging is a diagnostic and qualification action, not a mandatory operator step.

The controller records the selected discovery revision, exact names, requester, connection and authority. It prepares and audits the challenge route, guarded renewal setup, production order and HTTPS activation through the existing worker and native execution boundary. Each step uses its existing fresh admission, bounded payload, native lock, expiry, verification and recovery rules. Names and server identity must still match the authorization. Exact generated plans remain recorded, but the operator does not approve them separately.

Step completion and its local continuation task commit together. Every native step continues independently when the controller disconnects. Starting the next step needs the controller's worker; the installation is not one server-side transaction. An uncertain run pauses the sequence for **Check outcome** on the original unit. A failed or unverified step stops it. Neither an order nor a failed step is automatically replayed. A repeated successful request observes satisfied native state and performs no mutations.

## Consequences

The common certificate operation becomes one operator action. Individual plans remain under Advanced TLS diagnostics for inspection, staging and recovery. Permission checks, CSRF protection and private-key handling remain in force. Active installations protect their server registration between steps; completed records remain local audit when the registration is removed.

The shared native lock still excludes compatible controllers and renewal per mutation. There is no lock spanning all steps, and ordinary root administrators can bypass it. Intervening discovery is allowed; conflicting mutations can stop the sequence. This does not authorize adoption of custom layouts, changing domains, deleting data or retrying certificate orders.

The earlier qualification record describes the separate-plan interface on its named revisions. This interface and continuation require their own repository, browser and native qualification before release.

## Sources

- [CloudPanel certificate workflow](https://www.cloudpanel.io/docs/v2/frontend-area/tls/) documents domains followed by Create and Install. It is the operator interaction reference, not the execution implementation.
- [Certbot command-line options](https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options) document noninteractive operation and `--agree-tos`. The existing distribution-version-qualified Certbot integration is retained.
- [Django 6.1 transactions](https://docs.djangoproject.com/en/6.1/topics/db/transactions/) document committing related database writes together. Barectl's database-backed task queue participates in that same database transaction; no remote I/O takes place inside the continuation transaction.
