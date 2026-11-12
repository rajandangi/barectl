# Roadmap

[GitHub Releases](https://github.com/rajandangi/barectl/releases) lists published versions. [GitHub Issues](https://github.com/rajandangi/barectl/issues) tracks implementation and priorities.

## Next

**1.0.1** is the planned patch release for the dashboard improvements and runtime catalog refresh already implemented on `main`. These changes await publication. See [Unreleased changes](CHANGELOG.md#unreleased) and the [release qualification](docs/v1.0.1-qualification.md).

**1.1** includes the planned dashboard setting for journald log retention, deferred from 1.0 in [ADR 0043](docs/adr/0043-defer-log-retention-settings-to-1-1.md).

## Later

- Optional shared database for Barectl records across installations.
- Fleet overview and CLI parity.
- Tested team hosting with credential management.

## Released

[v1.0.0](https://github.com/rajandangi/barectl/releases/tag/v1.0.0) is the first official release. It delivers the capabilities below on the [supported hosting stack](docs/target-architecture.md), with stable configuration contracts and tested recovery procedures. [1.0 specification](https://github.com/rajandangi/barectl/issues/528) · [1.0 qualification](docs/v1.0-qualification.md)

| Phase | Shipped scope | Specification | Qualification |
| --- | --- | --- | --- |
| A | SSH connections, server setup, runtimes, plain PHP sites, and discovery from a fresh controller | [#325](https://github.com/rajandangi/barectl/issues/325) | [Phase A](docs/phase-a-qualification.md) |
| B | HTTPS, databases, WordPress, and Laravel deployment | [#356](https://github.com/rajandangi/barectl/issues/356) | [Phase B](docs/phase-b-qualification.md) |
| C | Site schedules, Laravel queues, Valkey, and log viewing | [#357](https://github.com/rajandangi/barectl/issues/357) | [Phase C](docs/phase-c-qualification.md) |
| D | Encrypted restic backups, offsite copies, and selective restore | [#358](https://github.com/rajandangi/barectl/issues/358) | [Phase D](docs/phase-d-qualification.md) |
| E | Scoped operator permissions, server security, and jobs reported by the server | [Security #301](https://github.com/rajandangi/barectl/issues/301), [Server Jobs #284](https://github.com/rajandangi/barectl/issues/284) | [Phase E](docs/phase-e-qualification.md) |

## Outside scope

Email hosting, billing, reseller management, DNS hosting, and container orchestration.
