# HTTPS

Every new site is served over HTTPS by Caddy's automatic HTTPS. Barectl adds no ACME client, renewal scheduler or renewal guard: Caddy owns issuance and renewal, and the site file uses bare host names ([ADR 0027](adr/0027-serve-sites-and-https-with-caddy.md)). An operator may create a site HTTP only from the create form's More options. The HTTP-only site file uses explicit `http://` addresses, so Caddy requests no certificate.

## Site file

An HTTPS site file uses bare host names:

```
shop.example.com, www.example.com {
    ...
}
```

An HTTP-only site file uses explicit `http://` addresses:

```
http://shop.example.com, http://www.example.com {
    ...
}
```

Caddy places its host-matched HTTP-to-HTTPS redirect routes before the shared `:80` catch-all, so unknown host names still answer 404 on HTTP and are refused on HTTPS (`strict_sni_host on`). The ACME challenge path is answered before the redirect, so issuance keeps working while HTTP requests redirect. The main configuration leaves automatic HTTPS on; it sets `admin` and `servers { strict_sni_host on }`, and imports the site files.

A host built before this change has `auto_https off` in its main configuration: discovery reads that as an older foundation, so the host reports **Incomplete foundation** and **Set up server** rewrites the main configuration and restarts Caddy. No site is recreated, and the earlier file is only replaced, never kept as a Barectl record.

The site file's route is otherwise unchanged from [the site convention](site-conventions.md#serving): the deny rules, the front-controller rewrite, the private HAProxy socket and the JSON access log.


## Changing names and HTTPS

A site's **Settings > Domains and HTTPS** section shows its names and whether HTTPS is on, and prepares one reviewed change. The change republishes the site's Caddy file with the new names and scheme, validates the whole Caddy tree, reloads Caddy and checks every name: the primary name answers, and a WordPress or Laravel alias redirects to the primary domain in the same file. A plain PHP site answers every name directly. The change is **Shared** because Caddy reloads for every site, and the review names the affected sites. A DNS name that does not resolve to the server is warned about and must be acknowledged; it never refuses the change.

Discovery reconstructs the names, the scheme and the serving form from the site file alone. A name that does not resolve to the server is a warning in the review, never a refusal. The site's certificate follows Caddy's automatic HTTPS for every name in the file.

## Certificate state

Barectl reads Caddy's own stored certificate files under its app data directory, not a Barectl marker. It parses each stored `.crt` with `openssl` for the names, the issuer and the expiry, and matches the site's host names. The site page shows one of:

| State | Evidence |
| --- | --- |
| Issued | a matching stored certificate, with its issuer and expiry |
| Renewal due | a matching certificate whose expiry is within 30 days |
| Waiting | no matching certificate and no recent issuance error |
| Failing | the last bounded Caddy journal line naming the site that reports an error |

An HTTP-only site reports "Not used (HTTP only)". A fresh controller reconstructs the HTTPS setting, the certificate state and the site's names from the site file and Caddy's storage alone ([site observations](ssh-connections.md#site-observations)).

## DNS

The create review resolves each requested name through the server's own resolver and compares the answers with the server's global addresses. A name that does not resolve to the server is a warning with an acknowledgement, never a refusal: a site behind a proxy or CDN is legitimate, and Caddy may still obtain a certificate. Barectl never edits DNS.

## Limits

Only the default challenges (HTTP-01 and TLS-ALPN-01) and the default issuers. Wildcard certificates, the DNS-01 challenge and uploaded certificates are out of scope: a DNS provider module needs a custom Caddy build, which the no-build Nix policy of [ADR 0028](adr/0028-supply-runtimes-and-tools-from-pinned-nix.md) forbids. Caddy has no status endpoint for certificates, so the state comes from its stored files, a TLS probe and bounded journal lines.

The published listener set of a target-stack host is SSH, 80/tcp, 443/tcp and 443/udp. Foundation verification refuses a host whose public listeners are anything else.
