#!/bin/sh
# Run the tests tagged ssh (discovery/test_remote.py, bootstrap/test_remote.py,
# bootstrap/test_apply_remote.py, bootstrap/test_coordination_remote.py,
# bootstrap/test_package_remote.py, bootstrap/test_php_remote.py,
# bootstrap/test_journey_remote.py and dashboard/test_browser_remote.py) against a fresh
# disposable server in Docker, once for each supported Ubuntu release. See
# docs/ssh-connections.md#acceptance-against-a-real-server and docs/quality.md#native-suites.
#
# BARECTL_DISPOSABLE_RELEASE names the releases to run, separated by spaces: "24.04",
# "26.04", or both, the default. Several releases run in parallel, each in its own run of
# this script with its output lines prefixed by the release, and the run fails if any
# release fails. When BARECTL_DISPOSABLE_RESULTS names a directory, each release that
# passes writes a file named after the release there, holding the server's architecture.
#
# The tests learn the server's release from BARECTL_SSH_TEST_RELEASE, and where the 26.04
# image serves its hosting provider's repository from BARECTL_SSH_TEST_PROVIDER_REPOSITORY.
# The container gets two throwaway keys, one per simulated controller. Its host key is read
# through docker exec, a trusted channel, which the tests also use to change fixtures and to
# restart the container's systemd. Arguments are passed to `uv run`, for example
# `--env-file .env`. The container and keys are removed on exit.
#
# Each run has its own container on a free local port, chosen here unless
# BARECTL_SSH_TEST_PORT sets one, so concurrent runs neither clash nor remove each other's
# container. The port is fixed when the container is created, so it stays the same when a
# test restarts the container. Runs share each release's image and its cache.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repository=$(cd "$here/../.." && pwd)
image=barectl-disposable-server
releases=${BARECTL_DISPOSABLE_RELEASE:-24.04 26.04}
work=$(mktemp -d)
count() { echo $#; }

# shellcheck disable=SC2086
if [ "$(count $releases)" -gt 1 ]; then
    if [ -n "${BARECTL_SSH_TEST_PORT:-}" ]; then
        echo "BARECTL_SSH_TEST_PORT fixes one port; set it only with one release." >&2
        exit 1
    fi
    results=${BARECTL_DISPOSABLE_RESULTS:-$work/results}
    mkdir -p "$results"
    pids=""
    # Background runs ignore SIGINT, so an interruption stops each release's process tree;
    # each release's own trap then removes its container.
    stop_tree() {
        children=$(pgrep -P "$1" 2>/dev/null || true)
        kill -TERM "$1" 2>/dev/null || true
        for child in $children; do stop_tree "$child"; done
    }
    interrupt() {
        trap - INT TERM
        for pid in $pids; do stop_tree "$pid"; done
        wait
        rm -rf "$work"
        exit 130
    }
    trap interrupt INT TERM
    trap 'rm -rf "$work"' EXIT
    started=$(date +%s)
    for release in $releases; do
        mkfifo "$work/$release.out"
        awk -v prefix="[$release] " '{ print prefix $0; fflush() }' <"$work/$release.out" &
        BARECTL_DISPOSABLE_RELEASE=$release BARECTL_DISPOSABLE_RESULTS=$results \
            "$here/run-tests.sh" "$@" >"$work/$release.out" 2>&1 &
        pids="$pids $!"
        echo "$release $!" >>"$work/runs"
    done
    failed=0
    while read -r release pid; do
        if wait "$pid"; then
            outcome="passed on $(cat "$results/$release")"
        else
            outcome=failed
            failed=1
        fi
        echo "  Ubuntu $release: $outcome" >>"$work/summary"
    done <"$work/runs"
    wait
    echo "Disposable-server tests after $(($(date +%s) - started)) seconds:"
    cat "$work/summary"
    exit "$failed"
fi

name=""
cleanup() {
    [ -z "$name" ] || docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

cp "$here/Dockerfile" "$here/provider-repository.sh" "$here/provider-repository.service" "$work/"
# Two independent controllers' keys, both authorized for both SSH users.
ssh-keygen -q -t ed25519 -N "" -f "$work/id"
ssh-keygen -q -t ed25519 -N "" -f "$work/id2"
cat "$work/id.pub" "$work/id2.pub" >"$work/authorized_keys"
free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

run_release() {
    release=$1
    shift
    case $release in
    24.04) provider="" ;;
    26.04) provider=/srv/provider-repository ;;
    *)
        echo "Unsupported release $release; choose 24.04 or 26.04." >&2
        exit 1
        ;;
    esac
    docker build -q --build-arg "RELEASE=$release" -t "$image:$release" "$work" >/dev/null
    name="$image-$release-$$-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
    # Another process can take the port between choosing and publishing it; choose again then.
    port=""
    for _ in 1 2 3 4 5; do
        candidate=${BARECTL_SSH_TEST_PORT:-$(free_port)}
        if docker run -d --privileged --name "$name" -p "127.0.0.1:$candidate:22" \
            "$image:$release" >/dev/null 2>"$work/run.err"; then
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
    # Record what this run qualifies: the server's architecture and native revisions.
    echo "Disposable server:"
    docker exec "$name" sh -c '. /etc/os-release; echo "$PRETTY_NAME $(uname -m)";
        php=$(dpkg-query -W -f="\${Package}\n" "php[0-9]*-fpm" 2>/dev/null | head -1);
        dpkg-query -W apt dpkg systemd util-linux sudo sudo-rs needrestart debconf nginx \
            packagekit ubuntu-helper-virt-hwe "$php" 2>/dev/null; readlink -f /usr/bin/sudo'
    architecture=$(docker exec "$name" uname -m)
    host_key=$(docker exec "$name" cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub)
    echo "[127.0.0.1]:$port $host_key" >"$work/known_hosts"

    (
        cd "$repository"
        BARECTL_SSH_TEST_HOST=127.0.0.1 \
            BARECTL_SSH_TEST_PORT="$port" \
            BARECTL_SSH_TEST_USER=deploy \
            BARECTL_SSH_TEST_KEY="$work/id" \
            BARECTL_SSH_TEST_KNOWN_HOSTS="$work/known_hosts" \
            BARECTL_SSH_TEST_SECOND_KEY="$work/id2" \
            BARECTL_SSH_TEST_UNPRIVILEGED_USER=observer \
            BARECTL_SSH_TEST_CONTAINER="$name" \
            BARECTL_SSH_TEST_RELEASE="$release" \
            BARECTL_SSH_TEST_PROVIDER_REPOSITORY="$provider" \
            uv run "$@" python manage.py test --tag ssh
    )
    docker rm -f "$name" >/dev/null 2>&1 || true
    name=""
    [ -z "${BARECTL_DISPOSABLE_RESULTS:-}" ] ||
        echo "$architecture" >"$BARECTL_DISPOSABLE_RESULTS/$release"
}

for release in $releases; do
    echo "Ubuntu $release:"
    run_release "$release" "$@"
done
