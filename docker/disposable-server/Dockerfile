# A disposable Ubuntu server for the tests tagged ssh (docs/ssh-connections.md), of the
# release RELEASE names: 24.04 or 26.04. run-tests.sh builds it with throwaway keys; systemd
# runs as PID 1.
#
# Besides SSH and sudo, it installs the Ubuntu server packages whose APT hooks form the
# tested distribution hook baseline (bootstrap/releases.py), including those Ubuntu's
# official server cloud image adds (packagekit, appstream and snapd), with apt-utils so that
# debconf's pre-install hook preconfigures packages as on an Ubuntu server, and
# systemd-sysv, whose /sbin/init invoke-rc.d needs before maintainer scripts such as
# php-fpm's may start their service. Ubuntu 26.04's ubuntu-minimal installs sudo-rs beside
# sudo, and sudo-rs provides /usr/bin/sudo; the image installs both the same way. It
# removes what only the Docker image has: the docker-clean hook, and the policy-rc.d that
# stops package maintainer scripts from starting services. deploy has noninteractive sudo,
# as bootstrap requires; observer has none, for the unprivileged refusal.
#
# The Ubuntu 26.04 image also carries a hosting provider's customizations, as recorded on a
# provider's 26.04 server: ubuntu-helper-virt-hwe's APT hook, an unowned lock timeout, and a
# signed third-party repository without an Origin, served on 127.0.0.1:8750.
ARG RELEASE=24.04

FROM ubuntu:${RELEASE} AS server
ARG RELEASE
ENV DEBIAN_FRONTEND=noninteractive
RUN case "$RELEASE" in 24.04) extra= ;; 26.04) extra="sudo-rs ubuntu-helper-virt-hwe" ;; *) exit 1 ;; esac \
 && apt-get update \
 && apt-get install -y --no-install-recommends systemd dbus openssh-server sudo $extra \
    iproute2 needrestart command-not-found ubuntu-pro-client update-notifier-common \
    apt-utils packagekit appstream snapd systemd-sysv \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/apt/apt.conf.d/docker-clean /usr/sbin/policy-rc.d \
 && systemctl enable ssh \
 && useradd --create-home --shell /bin/bash deploy \
 && install -d -m 700 -o deploy -g deploy /home/deploy/.ssh \
 && useradd --create-home --shell /bin/bash observer \
 && install -d -m 700 -o observer -g observer /home/observer/.ssh \
 && printf 'deploy ALL=(root) NOPASSWD: ALL\n' >/etc/sudoers.d/deploy \
 && chmod 440 /etc/sudoers.d/deploy
COPY --chown=deploy:deploy --chmod=600 authorized_keys /home/deploy/.ssh/authorized_keys
COPY --chown=observer:observer --chmod=600 authorized_keys /home/observer/.ssh/authorized_keys
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
