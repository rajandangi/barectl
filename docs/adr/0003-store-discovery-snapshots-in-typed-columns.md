# Store discovery snapshots in typed columns

Barectl stores a discovery snapshot as typed columns on `DiscoverySnapshot`, for the operating system and capacity observations and for the outcome, source and warning of the Nginx site file and PHP-FPM pool collections, with child tables for component observations, Nginx site files and PHP-FPM pools. A new kind of observation adds columns or a table through a migration. Barectl does not store one generic row per observation with a JSON value, nor one JSON document per snapshot.

Typed columns let the database enforce the domain: it refuses an absent operating system or capacity observation, and site files and pools are unique within their snapshot. Values keep their types for queries across servers. Only `discovery/snapshot.py` and the migrations know the layout, so changing it later touches that module alone. While Barectl makes no upgrade promise to existing installations, a migration per new observation costs little.

## Consequences

- Each new kind of observation needs a migration, and its database constraints are written with it.
- Several values are stored as newline-joined text, which only the snapshot module encodes and decodes.
- Revisit this decision when any of these holds:
  - Barectl keeps past snapshots to show what changed between discoveries, where uniform rows make comparisons generic.
  - Observations can be defined outside the code, such as configurable checks.
  - Barectl supports documented upgrades of existing installations, so each schema change is a migration operators run on their data.
