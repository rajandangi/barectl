"""Laravel release conventions on the Phase A site layout.

docs/target-architecture.md#laravel and the Phase B specification (#356) define the
convention this module words once:

- a release is ``/var/www/<identifier>/releases/<name>``, built in place as the site user
  and published by root only through the ``current`` link;
- shared state lives outside every release in the site's private area: the ``.env``, the
  application ``storage`` and the generated ``bootstrap/cache``;
- the repository URL and branch are native evidence read from the release's Git metadata,
  never a Barectl marker.
"""

from typing import Final

# The acknowledgement a Roll back's review requires and a forged apply cannot supply.
ROLLBACK_ACKNOWLEDGEMENT: Final = (
    "I understand a roll back swaps the code only. It does not reverse schema changes, "
    "data, uploads, storage, settings or queued jobs."
)

# How many releases a Deploy keeps besides ``current`` (Phase B settled decision 4).
RETAINED_RELEASES: Final = 5

# The maintenance gate: the site's Caddy file answering 503 for visitors while Caddy's
# automatic HTTPS challenge paths keep working (docs/target-architecture.md#laravel). The
# native body formats it, so it stays a reviewed, byte-stable string.
GATE_TEMPLATE: Final = """{addresses} {{
    @acme path /.well-known/acme-challenge/*
    handle @acme {{
        reverse_proxy unix/{settings.proxy_socket}
    }}
    @hidden {{
        path_regexp hidden (^|/)\\.[^/]+
        not path /.well-known/*
    }}
    route {{
        respond @hidden 404
        respond 503
    }}
    log {{
        output file {settings.directory}/logs/access.json {{
            roll_size 20MiB
            roll_keep 5
            roll_keep_for 14d
        }}
    }}
}}
"""
