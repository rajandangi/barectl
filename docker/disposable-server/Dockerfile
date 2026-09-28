# A disposable Ubuntu 24.04 server for the tests tagged ssh (docs/ssh-connections.md).
# run-tests.sh builds it with throwaway keys; systemd runs as PID 1.
#
# Besides SSH and sudo, it installs the Ubuntu server packages whose APT hooks form the
# tested distribution hook baseline (bootstrap/profiles.py), and removes the Docker image's
# own docker-clean hook, which no Ubuntu server has. deploy has noninteractive sudo, as
# bootstrap requires; observer has none, for the unprivileged refusal.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd dbus openssh-server sudo iproute2 \
    needrestart command-not-found ubuntu-pro-client update-notifier-common \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/apt/apt.conf.d/docker-clean \
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
