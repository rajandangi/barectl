#!/bin/sh
# docs/ssh-connections.md#acceptance-against-a-real-server
#
# The guest's host key is generated here, so the controller trusts the guest through a
# channel it controls rather than by scanning the network.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repository=$(cd "$here/../.." && pwd)
image=barectl-vm-server
release=${BARECTL_VM_RELEASE:-26.04}
case $release in
26.04) codename=resolute ;;
*)
    echo "Unsupported release $release; choose 26.04." >&2
    exit 1
    ;;
esac
name="$image-$$-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
work=$(mktemp -d)
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

ssh-keygen -q -t ed25519 -N "" -f "$work/id"
ssh-keygen -q -t ed25519 -N "" -f "$work/id2"
ssh-keygen -q -t ed25519 -N "" -C "" -f "$work/host"
mkdir "$work/seed"
indent() { sed 's/^/      /' "$1"; }
cat >"$work/seed/user-data" <<EOF
#cloud-config
users:
  - name: deploy
    shell: /bin/bash
    sudo: "ALL=(root) NOPASSWD: ALL"
    ssh_authorized_keys:
      - $(cat "$work/id.pub")
      - $(cat "$work/id2.pub")
  - name: observer
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$work/id.pub")
      - $(cat "$work/id2.pub")
ssh_pwauth: false
disable_root: true
ssh_genkeytypes: []
ssh_keys:
  ed25519_private: |
$(indent "$work/host")
  ed25519_public: $(cat "$work/host.pub")
# Ubuntu's periodic APT jobs would contend for the package locks at unpredictable times;
# contention itself is qualified by docker/disposable-server/run-tests.sh.
runcmd:
  - [systemctl, disable, --now, apt-daily.timer, apt-daily-upgrade.timer]
EOF
printf 'instance-id: barectl-vm\nlocal-hostname: barectl-vm\n' >"$work/seed/meta-data"

docker build -q --build-arg "CODENAME=$codename" -t "$image:$release" "$here" >/dev/null
free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
port=${BARECTL_SSH_TEST_PORT:-$(free_port)}
docker run -d --name "$name" -p "127.0.0.1:$port:22" -v "$work/seed:/seed:ro" "$image:$release" \
    >/dev/null
echo "[127.0.0.1]:$port $(cut -d' ' -f1-2 "$work/host.pub")" >"$work/known_hosts"

# The emulated first boot, with cloud-init, takes minutes.
admin() {
    ssh -q -i "$work/id" -p "$port" -o BatchMode=yes -o ConnectTimeout=10 \
        -o UserKnownHostsFile="$work/known_hosts" -o StrictHostKeyChecking=yes \
        deploy@127.0.0.1 "$@"
}
# cloud-init exits 2 when it finished with recoverable errors, such as deprecation warnings.
ready=""
for _ in $(seq 180); do
    if admin 'cloud-init status --wait >/dev/null 2>&1; [ $? -ne 1 ]' 2>/dev/null; then
        ready=yes
        break
    fi
    sleep 5
done
if [ -z "$ready" ]; then
    docker logs "$name" 2>&1 | tail -40 >&2
    echo "The virtual machine did not finish booting." >&2
    exit 1
fi
admin 'uname -m; . /etc/os-release; echo "$PRETTY_NAME"; uname -r;
    dpkg-query -W apt dpkg systemd util-linux sudo sudo-rs needrestart 2>/dev/null;
    readlink -f /usr/bin/sudo'

cd "$repository"
BARECTL_VM_TEST=1 \
    BARECTL_SSH_TEST_HOST=127.0.0.1 \
    BARECTL_SSH_TEST_PORT="$port" \
    BARECTL_SSH_TEST_USER=deploy \
    BARECTL_SSH_TEST_KEY="$work/id" \
    BARECTL_SSH_TEST_KNOWN_HOSTS="$work/known_hosts" \
    BARECTL_SSH_TEST_SECOND_KEY="$work/id2" \
    BARECTL_SSH_TEST_UNPRIVILEGED_USER=observer \
    BARECTL_SSH_TEST_CONTAINER="$name" \
    uv run "$@" python manage.py test --tag vm || {
    status=$?
    # The guest's serial console, which shows a boot or shutdown that did not finish.
    echo "The guest's console, last lines:" >&2
    docker logs "$name" 2>&1 | tail -80 >&2
    exit "$status"
}
