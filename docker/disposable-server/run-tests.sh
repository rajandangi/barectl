#!/bin/sh
# Run the tests tagged ssh (discovery/test_remote.py, bootstrap/test_remote.py,
# bootstrap/test_apply_remote.py and bootstrap/test_coordination_remote.py) against a fresh
# disposable server in Docker.
#
# The container gets two throwaway keys, one per simulated controller. Its host key is read
# through docker exec, a trusted channel, which the tests also use to change fixtures and to
# restart the container's systemd. Arguments are passed to `uv run`, for example
# `--env-file .env`. The container and keys are removed on exit.
#
# Each run has its own container on a free local port, chosen here unless
# BARECTL_SSH_TEST_PORT sets one, so concurrent runs, such as pushes from two worktrees,
# neither clash nor remove each other's container. The port is fixed when the container is
# created, so it stays the same when a test restarts the container. Runs share the image
# and its cache.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repository=$(cd "$here/../.." && pwd)
image=barectl-disposable-server
name="$image-$$-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
work=$(mktemp -d)
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

cp "$here/Dockerfile" "$work/"
# Two independent controllers' keys, both authorized for both SSH users.
ssh-keygen -q -t ed25519 -N "" -f "$work/id"
ssh-keygen -q -t ed25519 -N "" -f "$work/id2"
cat "$work/id.pub" "$work/id2.pub" >"$work/authorized_keys"
docker build -q -t "$image" "$work" >/dev/null
free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
# Another process can take the port between choosing and publishing it; choose again then.
port=""
for _ in 1 2 3 4 5; do
    candidate=${BARECTL_SSH_TEST_PORT:-$(free_port)}
    if docker run -d --privileged --name "$name" -p "127.0.0.1:$candidate:22" "$image" \
        >/dev/null 2>"$work/run.err"; then
        port=$candidate
        break
    fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    [ -z "${BARECTL_SSH_TEST_PORT:-}" ] || break
done
if [ -z "$port" ]; then
    cat "$work/run.err" >&2
    exit 1
fi

# systemd reports degraded when a unit fails that the tests do not use.
state=""
for _ in $(seq 60); do
    state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
    case $state in running | degraded) break ;; esac
    sleep 1
done
case $state in
running | degraded) ;;
*)
    echo "systemd did not start in the container (state: ${state:-unknown})." >&2
    exit 1
    ;;
esac

docker exec -i "$name" sh -s <"$here/provision.sh"
host_key=$(docker exec "$name" cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub)
echo "[127.0.0.1]:$port $host_key" >"$work/known_hosts"

cd "$repository"
BARECTL_SSH_TEST_HOST=127.0.0.1 \
    BARECTL_SSH_TEST_PORT="$port" \
    BARECTL_SSH_TEST_USER=deploy \
    BARECTL_SSH_TEST_KEY="$work/id" \
    BARECTL_SSH_TEST_KNOWN_HOSTS="$work/known_hosts" \
    BARECTL_SSH_TEST_SECOND_KEY="$work/id2" \
    BARECTL_SSH_TEST_UNPRIVILEGED_USER=observer \
    BARECTL_SSH_TEST_CONTAINER="$name" \
    uv run "$@" python manage.py test --tag ssh
