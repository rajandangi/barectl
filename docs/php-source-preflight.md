# PHP source metadata preflight

On 2026-10-07, a disposable-container preflight authenticated the unified PHP repository and simulated its proposed package profiles on Ubuntu 24.04 and 26.04, arm64. This is supporting evidence for [ADR 0016](adr/0016-limit-third-party-php-supply.md) and [#203](https://github.com/rajandangi/barectl/issues/203). It does not qualify installation or enable a Barectl workflow.

On 2026-10-10, [#345](https://github.com/rajandangi/barectl/issues/345) removed Ubuntu 24.04 support; Barectl supports Ubuntu 26.04 only. The Ubuntu 24.04 results in this record are historical evidence, not current support.

## Method and trust boundary

Each release used a fresh container from the repository's existing disposable-server image, before its PHP provisioning step. No PHP packages or keyring package were installed. The images already supplied native APT, `gpgv` and CA certificates. Their ordinary Ubuntu sources remained configured; the Resolute image's disposable provider source was removed inside this container because its local fixture service was not running. The containers and their source changes were removed after the preflight.

The [published public key](https://packages.sury.org/php/apt.gpg) downloaded over HTTPS had SHA-256 `b486fd5488185c4c46467960fa69c53d5085fec492cf76b9eaf3db33561c9d7c`. The preflight asserted that exact digest before copying it into a dedicated `/etc/apt/keyrings/sury-php.gpg`. The sole new deb822 source used `https://packages.sury.org/php/`, the release's own codename, `main`, `Architectures: arm64` and that file in `Signed-By`. It also set `Check-Valid-Until: yes` and `Valid-Until-Max: 604800`. No global trust changes, authentication overrides or global metadata-age settings were used.

The preferences used `Pin: release o=deb.sury.org,n=<current codename>`, with priority `-1` for `Package: *` and a separate priority `700` record listing only `php-common` and the exact `php8.3`, `php8.4` and `php8.5` binary names ending in `-fpm`, `-cli`, `-common`, `-readline`, `-opcache`, `-mysql` and `-pgsql`. The PHP record contained no wildcard. There was no `APT::Default-Release` setting or competing preference file in these fixtures.

Native update ran with `APT::Update::Error-Mode=any`, zero retries, bounded network timeouts and signature diagnostics. It exited zero for both releases. Native `gpgv --status-fd 1 --keyring ...` then verified the downloaded Sury `InRelease` and returned zero with `GOODSIG` and `VALIDSIG` for the full fingerprint `15058500A0235D97F5D10063B188E2B695BD4743`. Neither verification reported an expired or revoked signing key. This verifies signatures against the selected trust anchor; the HTTPS key download is not independent publisher-identity evidence.

The use and limitations of preferences follow the official [Noble APT preferences manual](https://manpages.ubuntu.com/manpages/noble/man5/apt_preferences.5.html). The [Resolute APT manual](https://manpages.ubuntu.com/manpages/resolute/man8/apt-get.8.html) documents simulation and update error handling. Selecting this source and the PHP allowlist are Barectl decisions.

## Authenticated metadata

| Ubuntu | Observed UTC time | APT | gpgv package | Sury metadata Date |
| --- | --- | --- | --- | --- |
| 24.04 | 2026-10-07 06:27:27 | 2.8.3 | 2.4.4-2ubuntu17.6 | 2026-10-01 12:01:15 UTC |
| 26.04 | 2026-10-07 06:27:44 | 3.2.0 | 2.4.8-4ubuntu3.1 | 2026-10-01 16:01:41 UTC |

The authenticated [Noble](https://packages.sury.org/php/dists/noble/InRelease) and [Resolute](https://packages.sury.org/php/dists/resolute/InRelease) metadata each named `Origin: deb.sury.org`, its own suite and codename, `main`, and architectures `amd64 arm64 armhf`. Only arm64 indexes and native execution were checked here. Neither file had `Valid-Until`.

Both APT versions accepted these six-day-old indexes with the source-specific seven-day maximum. Reducing only this source's `Valid-Until-Max` to `1` second and repeating strict update made each version exit `100` with the source's `InRelease is expired` error. This qualifies native enforcement of the maximum in these fixtures, including an index with no publisher expiry. Ubuntu's indexes still updated normally. The source-specific option is documented by the [Noble](https://manpages.ubuntu.com/manpages/noble/man5/sources.list.5.html) and [Resolute](https://manpages.ubuntu.com/manpages/resolute/man5/sources.list.5.html) source-list manuals. Seven days is Barectl's admission limit, not a publisher update cadence or SLA. If these metadata files remain unchanged, this limit expires on 2026-10-08 at 12:01:15 UTC for Noble and 16:01:41 UTC for Resolute. A future plan must then refuse until authenticated fresh metadata is available.

## Candidate packages and effective preferences

Every available allowlisted PHP binary had effective version priority `700`. The repository index itself displayed priority `-1`, as expected for the default source rule; the specific PHP record overrode it for those version candidates.

| Branch or shared package | Ubuntu 24.04 candidate | Ubuntu 26.04 candidate |
| --- | --- | --- |
| PHP 8.3 | `8.3.35-1+0~20260925.87+ubuntu24.04~1.gbp19383d` | `8.3.35-1+0~20260925.87+ubuntu26.04~1.gbp19383d` |
| PHP 8.4 | `8.4.26-1+0~20260925.56+ubuntu24.04~1.gbp80d95d` | `8.4.26-1+0~20260925.56+ubuntu26.04~1.gbp80d95d` |
| PHP 8.5 | `8.5.11-1+0~20260924.26+ubuntu24.04~1.gbpbcb504` | `8.5.11-1+0~20260924.26+ubuntu26.04~1.gbpbcb504` |
| `php-common` | `2:101~+0~20260503.72+ubuntu24.04~1.gbp7da167` | `2:101~+0~20260503.72+ubuntu26.04~1.gbp7da167` |

For each branch, FPM, CLI, common, readline, MySQL and PostgreSQL driver binaries were available at that branch's listed version. PHP 8.3 and 8.4 also had a separately packaged opcache binary at the same version. PHP 8.5 had no separate opcache package or candidate, and its simulations required none. Runtime opcache behavior was not inspected.

The repository offered non-PHP `libgd3`, but its version retained priority `-1`. The Ubuntu candidate remained `2.3.3-9ubuntu5` on Noble and `2.3.3-13ubuntu2` on Resolute at priority `500`. Excluded `php8.2-common` had priority `-1` and no candidate on either release. These observations establish effective preferences for these fixtures; competing preferences and target-release overrides remain qualification cases.

## Transaction simulations

For each branch, `apt-get --simulate --no-install-recommends install` requested its FPM, CLI, MySQL driver and PostgreSQL driver together. All six simulations exited zero, with zero upgrades and removals.

| Ubuntu | PHP 8.3 new packages | PHP 8.4 new packages | PHP 8.5 new packages |
| --- | --- | --- | --- |
| 24.04 | 11 | 11 | 10 |
| 26.04 | 12 | 12 | 11 |

New non-PHP dependencies were `psmisc`, `libpq5` and `libsodium23`, plus `libargon2-1` on Resolute. Their policy listings offered only Ubuntu versions at priority `500`; none appeared in the authenticated Sury package index. Noble already had Ubuntu's `libargon2-1`. The repository's non-PHP library offers were `libgd` and `libmpdec` binaries on Noble, and `libgd` and legacy `libpcre` binaries on Resolute. None intersected the new package sets of these six simulations. These transactions therefore show no current need to expand the PHP exception to third-party libraries. Future package revisions must be admitted again from their exact evidence. Any non-PHP transaction package offered by this repository, even at priority `-1`, must still refuse the plan.

## Limits and remaining work

This preflight downloaded metadata only. It did not download PHP archives, verify their reviewed digests, execute Barectl's inline APT guard, install packages, inspect maintainer scripts, start FPM, exercise driver runtime behavior, add a second branch, switch a site or reconstruct a server from a fresh controller. It supplies no amd64 qualification, commit statuses or passing native-suite result.

Source setup still needs guarded publication and recovery tests. Package qualification still needs key and preference drift, stale-index refusal through Barectl's workflow, unavailable release or architecture, non-PHP source overlap, competing sources and equal-version archives with different contents. Publishing a suite establishes current availability, not a publisher release-support commitment or security-update SLA.

The separate dependency-audit blocker [#221](https://github.com/rajandangi/barectl/issues/221) does not prevent this metadata preflight. It remains a merge gate until an upstream fix passes the unchanged audit; this evidence introduces no audit exception.
