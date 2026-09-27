# A disposable Ubuntu 24.04 server for discovery/test_remote.py (docs/ssh-connections.md).
# run-tests.sh builds it with a throwaway key; systemd runs as PID 1.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd dbus openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl enable ssh \
 && useradd --create-home --shell /bin/bash deploy \
 && install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
COPY --chown=deploy:deploy --chmod=600 id.pub /home/deploy/.ssh/authorized_keys
CMD ["/lib/systemd/systemd"]
