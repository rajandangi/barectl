# Security native contract

This document owns the fixed native grammar, the upstream operations Barectl reuses and the
recovery limits of the server's [Security section](security.md). It describes what Phase E
([#301](https://github.com/rajandangi/barectl/issues/301)) implements for fresh Ubuntu 26.04
servers on amd64 and arm64 ([ADR 0026](adr/0026-manage-fresh-hosts-on-one-target-stack.md)).
The [target architecture](target-architecture.md) and its ADRs own the surrounding stack;
[ADR 0023](adr/0023-change-server-access-with-native-confirm-or-revert.md) and
[ADR 0024](adr/0024-admit-exact-reviewed-upgrade-transactions.md) own the window and the
package transaction.

## Reuse

| Need | Upstream operation | Barectl adds |
| --- | --- | --- |
| Firewall | UFW 0.36.2 on Ubuntu 26.04: `ufw --force enable`, `ufw default`, `ufw allow`, `ufw delete`, `ufw logging`, `ufw --dry-run`, `ufw status verbose`, `ufw show added`. | Admission of the one standard and the confirm-or-revert window. Rule files are never edited directly. |
| SSH policy | OpenSSH 10.2 drop-ins in `/etc/ssh/sshd_config.d/`, included at the top of `sshd_config` so the first value read wins; `sshd -t` and `sshd -T`. | One fixed drop-in, validation and the confirm-or-revert window. |
| Automatic updates | unattended-upgrades as configured by Ubuntu; `debconf-set-selections` and `dpkg-reconfigure -f noninteractive unattended-upgrades`; `apt-daily.timer` and `apt-daily-upgrade.timer`. | Observation and a reviewed enable or disable. No second scheduler. |
| Package updates | APT and the package engine and guard ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md), [ADR 0024](adr/0024-admit-exact-reviewed-upgrade-transactions.md)); `apt-get -s`, `apt-cache policy`, `dpkg --audit`, needrestart. | Selection, disclosure and verification. |
| Restart | `systemctl reboot`; `/run/reboot-required` and `/run/reboot-required.pkgs`, shipped by `update-notifier-common`. | Refusal under active work and fresh-boot verification. |
| Confirm-or-revert | `systemd-run --on-active=` transient timer and service, `systemctl stop` of the timer, `flock -w`. | Fixed payloads only. |

Rejected: fail2ban and CrowdSec, a Barectl watchdog or agent, editing `user.rules` or
`before.rules`, writing the automatic-update files by hand, `apt-get upgrade` without exact
admission, scheduled reboots and Livepatch.

## Firewall standard

| Element | Fixed value |
| --- | --- |
| Package and service | `ufw` 0.36.2 from the Ubuntu archive, active and enabled at boot, `ENABLED=yes` in `/etc/ufw/ufw.conf`. A missing package is installed through the exact APT transaction. |
| IPv6 | `IPV6=yes` in `/etc/default/ufw`. |
| Defaults | incoming deny, outgoing allow, routed deny; logging low. |
| SSH ports | The effective `sshd -T` `port` lines, the `ListenStream` values of `ssh.socket` and the ports sshd actually listens on must agree, and the verified connection's server-side port must be one of them; otherwise every firewall action refuses. |
| Standard rules | `allow <port>/tcp` for every SSH port, `allow 80/tcp`, `allow 443/tcp` and `allow 443/udp`, on IPv4 and IPv6. |
| Operator rules | `allow <port[:port]>/<tcp|udp>` or `allow [proto tcp|udp] from <network> to any port <port[:port]>`; one IPv4 or IPv6 CIDR. No deny, reject, limit, interface, route or application-profile rules. |
| Not following | Any other `ufw show added` line, edited `before.rules` or `after.rules` compared with the package's conffile digest, an active non-UFW nftables or iptables filter ruleset, `firewalld` active, or Docker installed. |

Docker publishes ports through its own chains ahead of UFW, so a Docker host refuses every
firewall action ([Docker packet filtering](https://docs.docker.com/engine/network/packet-filtering-firewalls/)).
Provider firewalls and security groups are invisible to the server and are named as such.

Preparation runs each rule command with `ufw --dry-run` and records its digest. It does not
dry-run `ufw --force enable`: ufw 0.36.2 writes `ENABLED=yes` even under `--dry-run`, so the
body enables and validates the result under the lock. The body re-reads UFW's state and rule
list, applies only the reviewed commands, and verifies the standard.

The listener read flags any public listener outside SSH, 80/tcp, 443/tcp and 443/udp, naming
the process. Database engines, Valkey, PHP-FPM and HAProxy are expected on loopback or Unix
sockets.

## SSH sign-in policy

| Element | Fixed value |
| --- | --- |
| Drop-in | `/etc/ssh/sshd_config.d/00-barectl-sign-in.conf`, root:root 0644, sorted before cloud-init's `50-cloud-init.conf`. |
| Content | `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin prohibit-password`, or `PermitRootLogin no` when the verified connection signs in as a non-root user with the sudo authorization Barectl already requires. |
| Holds when | `sshd -T` reports the reviewed values, every listed login account's `sshd -T -C` result agrees, the accounts are readable and there is no unverifiable include or `Match` condition. |

The review lists accounts with a login shell and no readable `authorized_keys`. Phase A site
accounts use `/usr/sbin/nologin` and do not appear. Port, listen address, user, key and
multi-factor sign-in are outside this contract.

The body writes the drop-in, runs `sshd -t`, and reloads `ssh.service` when it is active.
Both `ssh.socket` and `ssh.service` are enabled on 26.04; this policy needs no socket
restart. OpenSSH 10.2 enables `PerSourcePenalties` by default; the section shows it and leaves
it unchanged.

## Confirm-or-revert window

[ADR 0023](adr/0023-change-server-access-with-native-confirm-or-revert.md) applies to
firewall and SSH changes. Under the mutation lock the body:

1. copies each file the change can touch into a root-only preimage under
   `/run/barectl/revert-<run>` (`/etc/ufw/user.rules`, `user6.rules`, `ufw.conf`,
   `/etc/default/ufw`, or the SSH drop-in and its absence), and records whether UFW was
   enabled;
2. arms `barectl-revert-<run>.timer` with `systemd-run --on-active=300`;
3. applies and validates the change;
4. exits, leaving the timer armed.

After a successful run the worker opens a **new** verified connection, not the one that
watched the run, and runs one fixed confirmation under the mutation lock. It stops the timer
and removes the preimage only when the revert service has no invocation and an empty control
group. A started revert is left alone. The page reports **Kept**, **Put back** or **Not
known** from the timer, service, preimage and journal.

The revert service is the only lock acquisition that waits: `flock -w 120`, restarted on
failure up to three times. It restores the preimage and runs `ufw --force disable` when UFW
was disabled before, otherwise `ufw reload`; for SSH it runs `sshd -t` and reloads. Every
engine payload refuses while a `barectl-revert-*` timer is active, its service is running or
failed, or a preimage remains. A restart inside the window keeps the new persistent
configuration and loses only the automatic put-back; the review says so.

## Automatic security updates

Ubuntu's standard is its own package, enabled by default: `unattended-upgrades` installed,
`APT::Periodic::Update-Package-Lists "1"` and `APT::Periodic::Unattended-Upgrade "1"`, the
package's allowed origins, no package blacklist, `Unattended-Upgrade::Automatic-Reboot` false,
and both `apt-daily.timer` and `apt-daily-upgrade.timer` enabled. Observation reads
`apt-config dump`, the two timers, the `50unattended-upgrades` conffile digest and the newest
log under `/var/log/unattended-upgrades/`.

Turn on and Turn off set `unattended-upgrades/enable_auto_updates` through
`debconf-set-selections` and run `dpkg-reconfigure -f noninteractive unattended-upgrades`.
The package's config script reads the current `20auto-upgrades` file before asking its
question, so the body first installs the package's own shipped enabled or disabled file
through `ucf`; a noninteractive reconfigure alone cannot change the answer. A missing
package is installed first through the exact APT transaction. Customized allowed origins, a
package blacklist, automatic reboot or a disabled timer are reported and left unchanged;
Turn on refuses them, while Turn off is offered because it only stops Ubuntu's own work.
Verification reads the effective values back.

`unattended-upgrades.service` is the distribution's shutdown helper, not update work. Every
payload's admission watches only `apt-daily.service` and `apt-daily-upgrade.service`
([#411](https://github.com/rajandangi/barectl/issues/411)).

## Pending updates and Install updates

Pending updates come from `apt-get -s -o APT::Get::Show-Versions=1 upgrade --with-new-pkgs`
and `apt-cache policy` against the current lists, without refreshing them. The list age comes
from the newest index time. A candidate from the release's `-security` suite is a security
update even when Ubuntu also copies it into `-updates`. Phased candidates kept back by APT
are waiting for Ubuntu's rollout; held and blocked updates are shown but never installed.

**Check for updates** runs `apt-get update` under the lock, changes no installed package, and
refreshes discovery. **Install updates** extends the same package engine rather than adding a
second path. The review names each selected package at its candidate version with
`--only-upgrade` and every new dependency. The inline guard admits only upgrade lines whose
old and new versions, architectures and archive match the review exactly. Removals,
downgrades, held packages, phased candidates, pending dpkg states and conffiles that differ
from dpkg's or ucf's recorded digests refuse before dpkg changes anything. Only the
authenticated Ubuntu 26.04 archive suites are accepted.

needrestart 3.11 or maintainer scripts may restart APT-owned services such as the database
engine, Valkey instances and SSH. The review names the active services and the sites they
serve, and states that Caddy, HAProxy and the PHP masters come from Nix and are not restarted
by Ubuntu updates. Barectl does not change needrestart's configuration.

Verification checks installed versions, `dpkg --audit`, the profile units, Caddy routing and
each site's readiness, then queues discovery and shows any new restart-needed evidence.

## Restart

The review names `/run/reboot-required.pkgs`, the affected sites and services, the expected
downtime, and that scheduled site tasks and queue workers stop and start again. Under the
mutation lock the body re-reads the restart-needed packages and refuses if they changed. It
also refuses while another `barectl-apply-*` unit, a `barectl-revert-*` timer or service, a
site backup, copy, integrity check or cleanup, or `apt-daily.service` or
`apt-daily-upgrade.service` has processes. Scheduled tasks and queue workers do not block:
they tick every minute ([ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md)),
so a refusal would almost never clear, and their jobs tolerate being stopped.

The body writes its one result line, which persistent journald keeps, then runs
`systemctl reboot`. The engine gains one kind-level option: success means a **new boot ID**.
After submission it opens a fresh verified connection and waits up to ten minutes. On a new
boot it reads the journal's result line and verifies that Caddy, each site's HAProxy and PHP
master, the database engine and every enabled Valkey instance are active, then each site's
readiness. With no connection it closes the run as outcome unknown with provider-console
guidance. Nothing is retried, so a broken boot is not made worse.

## Exclusion and recovery limits

Every payload refuses while `apt-daily.service` or `apt-daily-upgrade.service` has processes,
and while a confirm-or-revert window is open or its put-back failed. Unattended upgrades do
not take the Barectl lock; dpkg's frontend lock remains the package-level exclusion. An
unattended upgrade can restart MariaDB, PostgreSQL or Valkey through needrestart, so a Deploy
or a capture that loses its database connection must fail honestly rather than retry blindly.

A reverted change restores files and reloads the service; connections it dropped are not
restored. Install updates is not reversible; recovery is ordinary administration or a
backup. A server that does not return from a restart needs the provider console, and Barectl
never retries it.

## Cloud-image VM lane

A container shares the Docker host's kernel, so its boot ID cannot change and its defaults
are the image's, not a cloud image's. The scheduled **Native VM** workflow
(`.github/workflows/native-vm.yml`) boots the official Ubuntu 26.04 cloud image, pinned by
SHA-256 and size in `docker/disposable-server/cloud-image.json`, under QEMU and drives it over
SSH with the same `BARECTL_SSH_TEST_*` contract as the native scenarios. QEMU user networking
runs with `restrict=on`; the guest reaches only a NoCloud seed and the local mirror through
`guestfwd` proxies. The lane proves a real kernel reboot changes
`/proc/sys/kernel/random/boot_id` and that SSH returns, and it is the home of the real-restart
scenario. It is never a required check and adds nothing to the merge build. See
[quality](quality.md#the-cloud-image-vm-lane).
