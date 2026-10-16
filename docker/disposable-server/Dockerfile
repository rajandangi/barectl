# docs/quality.md#native-layer: the disposable native images. L0 is a plain Ubuntu release
# server for the target stack; L0-standing adds the web packages the standing scenarios
# remove. Both carry the fixture CA the local mirror is served under.
#
# The installed packages' APT hooks form the tested hook baseline for the package and
# service observations. apt-utils lets debconf's pre-install hook preconfigure packages as
# on an Ubuntu server. systemd-resolved is part of Ubuntu server; Docker keeps its own
# /etc/resolv.conf, so resolved serves only resolvectl, and name lookups through glibc
# still use Docker's resolver.
ARG RELEASE=26.04
# Recordings build the server from the digest in pins.json (docs/quality.md#recorded-transcripts).
ARG BASE=ubuntu:${RELEASE}

FROM ${BASE} AS l0
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd dbus openssh-server sudo sudo-rs \
    iproute2 ca-certificates curl rsyslog python3-minimal xz-utils \
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

# A native-only image with the web packages preloaded. Scenarios remove the families they
# are not exercising, so discovery runs offline against real dpkg and systemd state.
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
