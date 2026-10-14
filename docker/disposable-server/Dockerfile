# docs/ssh-connections.md#acceptance-against-a-real-server
#
# The installed packages' APT hooks form the tested hook baseline (bootstrap/releases.py).
# apt-utils lets debconf's pre-install hook preconfigure packages as on an Ubuntu server.
# systemd-resolved is part of Ubuntu server; Docker keeps its own /etc/resolv.conf, so resolved
# serves only resolvectl, and name lookups through glibc still use Docker's resolver.
ARG RELEASE=26.04
# Recordings build the server from the digest in pins.json (docs/quality.md#recorded-transcripts).
ARG BASE=ubuntu:${RELEASE}

# docs/ssh-connections.md#php-source-fixture
FROM ubuntu:${RELEASE} AS php-source-fixture
ARG PHP_SOURCE_DIGEST
ARG PHP_SOURCE_FINGERPRINT
ARG PHP_SOURCE_PACKAGES
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates gpg gpg-agent apt-utils openssl
COPY php-source-fixture.sh /
RUN sh /php-source-fixture.sh /srv/php-source-fixture

FROM ubuntu:${RELEASE} AS provider-repository
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends gpg gpg-agent apt-utils
COPY provider-repository.sh /
RUN sh /provider-repository.sh /srv/provider-repository

FROM ${BASE} AS server
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd dbus openssh-server sudo sudo-rs \
    ubuntu-helper-virt-hwe \
    iproute2 needrestart command-not-found ubuntu-pro-client update-notifier-common \
    apt-utils packagekit appstream snapd systemd-sysv systemd-resolved ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/apt/apt.conf.d/docker-clean /usr/sbin/policy-rc.d \
 && rm -f /etc/ssh/ssh_host_* \
 && systemctl enable ssh \
 && useradd --create-home --shell /bin/bash deploy \
 && install -d -m 700 -o deploy -g deploy /home/deploy/.ssh \
 && useradd --create-home --shell /bin/bash observer \
 && install -d -m 700 -o observer -g observer /home/observer/.ssh \
 && printf 'deploy ALL=(root) NOPASSWD: ALL\n' >/etc/sudoers.d/deploy \
 && chmod 440 /etc/sudoers.d/deploy \
 && install -d -m 700 /root/.ssh
COPY --from=php-source-fixture /srv/php-source-fixture /srv/php-source-fixture
COPY php_source_fixture.py /srv/php-source-fixture/
RUN install -m 644 /srv/php-source-fixture/ca.crt \
    /usr/local/share/ca-certificates/barectl-php-source-fixture.crt \
 && update-ca-certificates >/dev/null
COPY --from=provider-repository /srv/provider-repository /srv/provider-repository
COPY provider-repository.service /etc/systemd/system/
RUN install -D -m 644 /srv/provider-repository/provider.gpg /etc/apt/keyrings/provider.gpg \
 && rm /srv/provider-repository/provider.gpg \
 && ln -s clean /srv/provider-repository/current \
 && printf '%s\n' 'Types: deb' 'URIs: http://127.0.0.1:8750/' 'Suites: resolute' \
    'Components: main' 'Signed-By: /etc/apt/keyrings/provider.gpg' \
    >/etc/apt/sources.list.d/provider.sources \
 && printf 'DPkg::Lock::Timeout "60";\n' >/etc/apt/apt.conf.d/99lock-timeout \
 && systemctl enable provider-repository
# docs/quality.md#how-a-run-is-split describes SSH keys generated at container startup.
ENTRYPOINT ["/bin/sh", "-c", "ssh-keygen -A >/dev/null && exec \"$@\"", "--"]
CMD ["/lib/systemd/systemd"]

# docs/quality.md#native-layer: L0, a plain Ubuntu 26.04 server for the target stack. It
# carries no old-stack package, only the fixture CA the local mirror is served under. The
# server image ships rsyslog and forwards to it, as the published cloud image does (spike
# P6.6); Python comes with Ubuntu server and runs the harness's own mirror containers.
FROM ${BASE} AS l0
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd dbus openssh-server sudo sudo-rs \
    iproute2 ca-certificates rsyslog python3-minimal xz-utils \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/apt/apt.conf.d/docker-clean /usr/sbin/policy-rc.d \
 && rm -f /etc/ssh/ssh_host_* \
 && systemctl enable ssh rsyslog \
 && install -d -m 700 /root/.ssh \
 && install -d /etc/systemd/journald.conf.d \
 && printf '[Journal]\nForwardToSyslog=yes\n' >/etc/systemd/journald.conf.d/forward.conf
COPY fixture-ca.crt /usr/local/share/ca-certificates/barectl-fixture-ca.crt
RUN update-ca-certificates >/dev/null
ENTRYPOINT ["/bin/sh", "-c", "ssh-keygen -A >/dev/null && exec \"$@\"", "--"]
CMD ["/lib/systemd/systemd"]

# A native-only image with the old web packages preloaded. Scenarios remove the families
# they are not exercising, so discovery runs offline against real dpkg and systemd state.
FROM ${BASE} AS l0-standing
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd dbus openssh-server sudo sudo-rs \
    iproute2 ca-certificates rsyslog python3-minimal xz-utils nginx apache2 php8.5-fpm \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/apt/apt.conf.d/docker-clean /usr/sbin/policy-rc.d \
 && rm -f /etc/ssh/ssh_host_* \
 && systemctl enable ssh rsyslog \
 && install -d -m 700 /root/.ssh \
 && install -d /etc/systemd/journald.conf.d \
 && printf '[Journal]\nForwardToSyslog=yes\n' >/etc/systemd/journald.conf.d/forward.conf
COPY fixture-ca.crt /usr/local/share/ca-certificates/barectl-fixture-ca.crt
RUN update-ca-certificates >/dev/null
ENTRYPOINT ["/bin/sh", "-c", "ssh-keygen -A >/dev/null && exec \"$@\"", "--"]
CMD ["/lib/systemd/systemd"]
