# Security native contract

Accepted design supporting [v0.9](v0.9.md). Implementation and qualification remain pending. This document owns the fixed native grammar, upstream reuse decisions and recovery limits. Values marked as policy are Barectl's choices, not upstream requirements. Facts marked "verify" must be confirmed against both supported releases in the slice that depends on them, with the result recorded in its issue.

## Reuse

| Need | Upstream operation | Barectl adds |
| --- | --- | --- |
| Firewall | UFW 0.36.2 on Ubuntu 24.04 and 26.04: `ufw --force enable`, `ufw default`, `ufw allow`, `ufw delete`, `ufw logging`, `ufw --dry-run`, `ufw status verbose`, `ufw show added`. | Admission of the one standard and the confirm-or-revert window. Rule files are never edited directly. |
| SSH policy | OpenSSH drop-ins in `/etc/ssh/sshd_config.d/`, included at the top of `sshd_config` so the first value read wins; `sshd -t` and `sshd -T`. | One fixed drop-in, validation and the confirm-or-revert window. |
| Automatic updates | unattended-upgrades as configured by Ubuntu; `dpkg-reconfigure -f noninteractive unattended-upgrades` with the package's debconf answer; `apt-daily.timer` and `apt-daily-upgrade.timer`. | Observation and a reviewed enable or disable. No second scheduler. |
| Package updates | APT and the existing package engine and guard ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md), [ADR 0024](adr/0024-admit-exact-reviewed-upgrade-transactions.md)); `apt-get -s` simulation; needrestart's packaged behavior. | Selection, disclosure and verification. |
| Restart | `systemctl reboot`; `/run/reboot-required` and `/run/reboot-required.pkgs` (verify `.pkgs` on both releases). | Refusal under active work, fresh-boot verification. |
| Revert timer | `systemd-run --on-active=` transient timer and service, `systemctl stop` of the timer. | Fixed payloads only. |

Rejected: fail2ban and CrowdSec (another daemon and rule set, unnecessary with key-only sign-in), a Barectl watchdog or agent, editing `user.rules`, writing `20auto-upgrades` by hand, `apt-get upgrade` without exact admission, scheduled reboots and Livepatch.

## Firewall standard

| Element | Fixed value |
| --- | --- |
| Package and service | `ufw` installed from the release, `ufw.service` enabled, `ENABLED=yes` in `/etc/ufw/ufw.conf`. A missing package is installed through a reviewed bootstrap package profile first. |
| IPv6 | `IPV6=yes` in `/etc/default/ufw` (the package default). Any other value does not follow the standard. |
| Defaults | incoming deny, outgoing allow, routed deny; logging low. |
| SSH ports | The effective `sshd -T` `port` lines, the `ListenStream` values of `ssh.socket` where it is enabled, and the ports sshd actually listens on must agree, and the verified connection's port must be one of them; otherwise every firewall action refuses. |
| Standard rules | `allow <port>/tcp` for every SSH port, `allow 80/tcp`, `allow 443/tcp`, each for IPv4 and IPv6. |
| Operator rules | `allow [proto tcp|udp] from <network> to any port <port[:port]>` or `allow <port[:port]>/<tcp|udp>`; one network per rule, a valid IPv4 or IPv6 CIDR. No deny, reject, limit, interface, route or application-profile rules. |
| Not following | Any other `ufw show added` line, edited `before.rules`/`after.rules` compared with the package's conffile digest, an active nftables or iptables ruleset not produced by UFW, `firewalld` active, or Docker installed. |

Docker publishes ports through its own chains ahead of UFW's rules, so a server with Docker refuses every firewall action ([Docker packet filtering](https://docs.docker.com/engine/network/packet-filtering-firewalls/)). Provider firewalls and security groups are invisible to the server and are named as such in the review.

The plan runs `ufw --dry-run` for each command during preparation and records the result digest. The payload revalidates the effective SSH ports, UFW state and rule list under the lock before applying.

## SSH sign-in policy

| Element | Fixed value |
| --- | --- |
| Drop-in | `/etc/ssh/sshd_config.d/00-barectl-sign-in.conf` (policy), root:root 0644, exactly the lines below. It sorts before cloud-init's `50-cloud-init.conf`, which may set `PasswordAuthentication yes`. |
| Content | `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin prohibit-password` or `PermitRootLogin no`. |
| Root choice | `no` only when the verified connection signs in as a non-root user with the sudo rights Barectl already requires; otherwise `prohibit-password`. |
| Holds when | `sshd -T` reports `passwordauthentication no`, `kbdinteractiveauthentication no` and the chosen `permitrootlogin`. A `Match` block that re-enables passwords is reported through `sshd -T -C` for the accounts listed in the review. |

The payload writes the drop-in, runs `sshd -t`, and reloads `ssh.service` when it is active. On Ubuntu 24.04 SSH is socket-activated; a daemon started later reads the new file. Port and `ListenAddress` changes, which need the socket generator and `ssh.socket` restart, are outside the standard. The review lists accounts with a login shell and no readable `authorized_keys` as accounts that will lose password sign-in.

OpenSSH 10.2 on Ubuntu 26.04 enables `PerSourcePenalties` by default; OpenSSH 9.6 on Ubuntu 24.04 predates it ([release 9.8](https://www.openssh.org/txt/release-9.8)). The review states which applies.

## Confirm-or-revert window

[ADR 0023](adr/0023-change-server-access-with-native-confirm-or-revert.md) applies to firewall and SSH plans.

1. Under the shared mutation lock and the [ADR 0006](adr/0006-use-native-bootstrap-execution.md) checks, copy each file the change can touch (`/etc/ufw/user.rules`, `user6.rules`, `ufw.conf`, `/etc/default/ufw`, or the SSH drop-in and its absence) into a root-only recovery preimage directory named after the run's unit under `/run/barectl` (verify the exact UFW file set on both releases).
2. Arm `barectl-revert-<run>.timer` with `systemd-run --on-active=300` (policy: five minutes). Its service waits up to two minutes for the mutation lock (`flock -w 120`, the only waiting acquisition) and is restarted on failure up to three times, so a running renewal or backup delays the revert instead of cancelling it. It restores the preimage, then runs `ufw --force disable` when the preimage has `ENABLED=no` (UFW skips `reload` while disabled, which would leave the new rules loaded), otherwise `ufw reload`; for SSH it runs `sshd -t` and reloads SSH.
3. Apply and validate the change, then exit. The timer remains.
4. The worker opens a new verified SSH connection with the registration's normal settings and runs one fixed confirmation under the mutation lock: stop the timer, then remove the preimage only when the revert service has no invocation ID and an empty control group. If the revert service has started, the confirmation leaves everything in place and reports the window as reverted or reverting.

The window is reported as confirmed, reverted, or unknown. Every mutation payload, including the restart, refuses while any `barectl-revert-*.timer` is active, any `barectl-revert-*.service` is running or failed, or a preimage directory under `/run/barectl` remains; a failed revert needs ordinary administration, which the run's guidance describes. A reboot inside the window loses the transient timer and `/run`, so the new persistent configuration stays; the review says so. Precedents: [netplan try](https://manpages.ubuntu.com/manpages/noble/en/man8/netplan-try.8.html) and [iptables-apply](https://manpages.ubuntu.com/manpages/noble/en/man8/iptables-apply.8.html).

## Automatic security updates

Ubuntu installs unattended-upgrades and enables security updates by default through `/etc/apt/apt.conf.d/20auto-upgrades` with `APT::Periodic::Update-Package-Lists "1"` and `APT::Periodic::Unattended-Upgrade "1"`; `Unattended-Upgrade::Automatic-Reboot` defaults to false ([Ubuntu automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/)). The standard is exactly that state. Observation reads `apt-config dump` for effective values, timer enablement, the package's conffile digest for `50unattended-upgrades` and the latest log under `/var/log/unattended-upgrades/`. Changed allowed origins, package blacklists, automatic reboot or a disabled timer are reported and left alone; enabling refuses them.

Turn on and Turn off run `dpkg-reconfigure -f noninteractive unattended-upgrades` after setting `unattended-upgrades/enable_auto_updates` through `debconf-set-selections`. Verification reads the effective values back.

## Pending updates and Install updates

Pending updates come from `apt-get -s -o APT::Get::Show-Versions=1 upgrade --with-new-pkgs` and `apt-cache policy` against current lists without refreshing them, with list age from the newest index time. Security means a candidate from the release's `-security` suite. Phased candidates kept back by APT are "waiting for Ubuntu's rollout"; security updates are never phased ([phased updates](https://ubuntu.com/server/docs/explanation/software/about-apt-upgrade-and-phased-updates/)).

The plan installs with the existing engine's `apt-get install --only-upgrade <package>=<version>…`, the inline guard admitting exactly the reviewed upgrade and new-package lines. It refuses held packages, any removal, a package whose installed conffiles differ from dpkg's recorded digests (`dpkg-query -W -f='${Conffiles}'`) or whose ucf-managed files differ from `/var/lib/ucf/hashfile`, pending states and candidates outside the release's Ubuntu origins and the approved PHP source.

needrestart on Ubuntu 24.04 restarts affected services automatically in unattended runs ([needrestart changes](https://discourse.ubuntu.com/t/needrestart-changes-in-ubuntu-24-04-service-restarts/44671)); the review lists the services it would restart from `needrestart -b -r l` style simulation where available, and otherwise every service of a package in the transaction (verify on both releases). Barectl does not change needrestart's configuration.

## Restart

The payload, under the mutation lock, refuses while any finite unit has processes: `barectl-apply-*`, `barectl-revert-*` (timer or service), `certbot.service`, a site backup or `s<identifier>-backup-retention.service`, a Laravel scheduler invocation, `apt-daily.service` or `apt-daily-upgrade.service`. Long-running Laravel queue workers do not block; the review discloses that systemd stops them within their stop budget and starts them after boot. It records nothing on the server, then runs `systemctl reboot`. The worker waits, then connects with the registration's normal settings and verified host key. A different boot ID, the profile units active and site serving readiness close the run as verified. No connection within ten minutes (policy) leaves the run as outcome unknown; Check outcome may later observe the new boot.

## Exclusion

Every mutation payload adds two refusals beside the Certbot check: a populated `apt-daily.service` or `apt-daily-upgrade.service` control group, and an active `barectl-revert-*.timer`. Exit codes are assigned in the implementing slice and recorded with ADR 0006's table. unattended-upgrades does not take the Barectl lock; dpkg's frontend lock remains the package-level exclusion and existing payloads already fail at once on it. The other direction is not fenced: an unattended upgrade that starts during a v0.5 release activation or a v0.6 full capture or restore can restart PHP-FPM or Nginx through needrestart or maintainer scripts. Those workflows must recheck that the apt-daily units are idle and their drained services are still stopped before reading data and before resuming; until they do, this is a documented limit in their reviews.

## Recovery limits

- A reverted change restores files and reloads the service; connections the change dropped are not restored.
- Install updates is not reversible. Downgrades are refused, so recovery is ordinary administration or a backup.
- A restart that does not return needs the provider console. Barectl never retries it.
- Changes made with ordinary tools during the window are overwritten by a revert of the same files; the review says so.
