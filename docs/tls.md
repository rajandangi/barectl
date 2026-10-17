# HTTPS

Sites on `main` serve HTTP only: each Caddy site file uses explicit `http://` addresses and the main configuration turns automatic HTTPS off, so Caddy requests no certificate ([site convention](site-conventions.md#serving)).

HTTPS is planned in the [Phase B specification](https://github.com/rajandangi/barectl/issues/356).
