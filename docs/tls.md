# HTTPS

Accepted Phase B design; not implemented. Sites on `main` serve HTTP only: each Caddy site file uses explicit `http://` addresses and the main configuration turns automatic HTTPS off, so Caddy requests no certificate ([site convention](site-conventions.md#serving)).

Phase B adds a reviewed HTTPS workflow in which Caddy owns certificate issuance and renewal through its [automatic HTTPS](https://caddyserver.com/docs/automatic-https), replacing Barectl's earlier Certbot setup, renewal guard and activation steps ([ADR 0027](adr/0027-serve-sites-and-https-with-caddy.md)). The accepted direction, from the [target architecture](target-architecture.md#caddy):

- A site's change from HTTP to HTTPS is a reviewed change of its Caddy site file, published through the same whole-tree validation, guarded reload and restore as site creation.
- Caddy has no certificate status command or endpoint, so discovery reports certificate state from Caddy's stored certificate files, a TLS probe and the journal.
- The server's own DNS answers and addresses are review evidence; Barectl does not create or edit DNS records.
- The firewall standard of Phase E allows SSH, 80/tcp, 443/tcp and 443/udp only.
- Native tests point Caddy at a local ACME server through `acme_ca` and `acme_ca_root`.

The Phase B specification and its tickets will define the workflow, permissions and recovery.
