#!/bin/sh
# Run discovery/test_remote.py against a fresh disposable server in Docker.
#
# The container gets a throwaway key; its host key is read through docker exec, a trusted
# channel. Arguments are passed to `uv run`, for example `--env-file .env`. The container
# and key are removed on exit.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repository=$(cd "$here/../.." && pwd)
name=barectl-disposable-server
port=${BARECTL_SSH_TEST_PORT:-2222}
work=$(mktemp -d)
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

cp "$here/Dockerfile" "$work/"
ssh-keygen -q -t ed25519 -N "" -f "$work/id"
docker build -q -t "$name" "$work" >/dev/null
docker run -d --rm --privileged --name "$name" -p "127.0.0.1:$port:22" "$name" >/dev/null

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
    uv run "$@" python manage.py test --tag ssh
