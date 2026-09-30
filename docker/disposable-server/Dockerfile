# docs/ssh-connections.md#acceptance-against-a-real-server
#
# The installed packages' APT hooks form the tested hook baseline (bootstrap/releases.py).
# apt-utils lets debconf's pre-install hook preconfigure packages as on an Ubuntu server.
# systemd-resolved is part of Ubuntu server; Docker keeps its own /etc/resolv.conf, so resolved
# serves only resolvectl, and name lookups through glibc still use Docker's resolver.
ARG RELEASE=24.04

FROM ubuntu:${RELEASE} AS server
ARG RELEASE
ENV DEBIAN_FRONTEND=noninteractive
RUN case "$RELEASE" in 24.04) extra= ;; 26.04) extra="sudo-rs ubuntu-helper-virt-hwe" ;; *) exit 1 ;; esac \
 && apt-get update \
 && apt-get install -y --no-install-recommends systemd dbus openssh-server sudo $extra \
    iproute2 needrestart command-not-found ubuntu-pro-client update-notifier-common \
    apt-utils packagekit appstream snapd systemd-sysv systemd-resolved \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/apt/apt.conf.d/docker-clean /usr/sbin/policy-rc.d \
 && systemctl enable ssh \
 && useradd --create-home --shell /bin/bash deploy \
 && install -d -m 700 -o deploy -g deploy /home/deploy/.ssh \
 && useradd --create-home --shell /bin/bash observer \
 && install -d -m 700 -o observer -g observer /home/observer/.ssh \
 && printf 'deploy ALL=(root) NOPASSWD: ALL\n' >/etc/sudoers.d/deploy \
 && chmod 440 /etc/sudoers.d/deploy \
 && install -d -m 700 /root/.ssh
COPY --chown=deploy:deploy --chmod=600 authorized_keys /home/deploy/.ssh/authorized_keys
COPY --chown=observer:observer --chmod=600 authorized_keys /home/observer/.ssh/authorized_keys
# Ubuntu's sshd lets root sign in with a key, as a root SSH identity does.
COPY --chmod=600 authorized_keys /root/.ssh/authorized_keys
CMD ["/lib/systemd/systemd"]

FROM ubuntu:${RELEASE} AS provider-repository
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends gpg gpg-agent apt-utils
COPY provider-repository.sh /
RUN sh /provider-repository.sh /srv/provider-repository

FROM server AS server-24.04

FROM server AS server-26.04
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

FROM server-${RELEASE}
