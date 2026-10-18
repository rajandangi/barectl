# docs/quality.md#native-layer: the lane's fixture Git host. It carries Git and the OpenSSH
# server so a scenario server clones the fixture repository over HTTPS (git_http.py) and
# SSH, all on the lane's internal network. Kept out of the main Dockerfile so adding it
# does not rebuild the L0 and L1 snapshots.
ARG RELEASE=26.04
ARG BASE=ubuntu:${RELEASE}

FROM ${BASE} AS fixture
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-server python3 \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_* \
 && useradd -m -d /home/git -s /usr/bin/git-shell git
COPY fixture-ca.crt /usr/local/share/ca-certificates/barectl-fixture-ca.crt
RUN update-ca-certificates >/dev/null
# The fixture repository is the Laravel application the Composer mirror is built from, so
# the same commit the lane clones is the lock the mirror serves. It lives under the git
# user's home so git-shell accepts the relative path an SSH clone sends.
COPY fixtures/laravel-app /fixtures/laravel-app
RUN git init --bare -q /home/git/fixture.git \
 && git -C /fixtures/laravel-app init -q \
 && git -C /fixtures/laravel-app symbolic-ref HEAD refs/heads/main \
 && git -C /fixtures/laravel-app config user.email fixture@barectl.test \
 && git -C /fixtures/laravel-app config user.name fixture \
 && git -C /fixtures/laravel-app add -A \
 && git -C /fixtures/laravel-app commit -qm fixture \
 && git -C /fixtures/laravel-app push -q /home/git/fixture.git main \
 && rm -rf /fixtures/laravel-app/.git \
 && git -C /home/git/fixture.git symbolic-ref HEAD refs/heads/main \
 && chown -R git:git /home/git/fixture.git \
 && git config --system --add safe.directory /home/git/fixture.git
ENTRYPOINT ["/bin/sh", "-c", "exec \"$@\"", "--"]
CMD ["/bin/sh"]
