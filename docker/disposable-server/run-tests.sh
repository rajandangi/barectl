#!/bin/sh
# docs/ssh-connections.md#acceptance-against-a-real-server
#
# When BARECTL_DISPOSABLE_RESULTS names a directory, each release that passes writes a file
# named after the release there, holding the server's architecture.
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

# The ACME and DNS fixtures: docs/ssh-connections.md#acme-and-dns-fixtures
pebble=ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199
challtestsrv=ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b

name=""
network=""
containers=""
remove_release() {
    for container in $containers; do
        docker rm -f "$container" >/dev/null 2>&1 || true
    done
    containers=""
    name=""
    [ -z "$network" ] || docker network rm "$network" >/dev/null 2>&1 || true
    network=""
}
cleanup() {
    remove_release
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
random_hex() {
    od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
}

# Each release's network has its own IPv6 prefix, so parallel runs never share one.
create_network() {
    network=$name
    ipv6_unavailable=""
    for _ in 1 2 3 4 5; do
        if docker network create --ipv6 --subnet "fd00:bc:$(random_hex 2)::/64" "$network" \
            >/dev/null 2>"$work/network.err"; then
            return
        fi
    done
    ipv6_unavailable="Docker could not create an IPv6 network: $(tr '\n' ' ' <"$work/network.err")"
    echo "$ipv6_unavailable; the IPv6 fixture tests will skip." >&2
    docker network create "$network" >/dev/null
}

pebble_config() {
    cat <<EOF
{
  "pebble": {
    "listenAddress": ":14000",
    "managementListenAddress": ":15000",
    "certificate": "$1",
    "privateKey": "$2",
    "httpPort": 80,
    "tlsPort": 443,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "domainBlocklist": ["blocked.barectl.test"],
    "retryAfter": {"authz": 3, "order": 5},
    "keyAlgorithm": "ecdsa",
    "profiles": {"default": {"description": "Barectl fixture", "validityPeriod": $3}}
  }
}
EOF
}

# Pebble's own TLS certificate names only localhost and pebble, so the other fixtures get one
# from the same test root, which the tests install on the disposable server.
start_fixtures() {
    acme=$work/acme
    mkdir -p "$acme/pebble" "$acme/pebble-short" "$acme/proxy"
    containers="$containers $name-certificates"
    docker create --name "$name-certificates" "$pebble" >/dev/null
    docker cp "$name-certificates:/test/certs/pebble.minica.pem" "$acme/minica.pem" >/dev/null
    docker cp "$name-certificates:/test/certs/pebble.minica.key.pem" "$acme/minica.key" >/dev/null
    docker rm "$name-certificates" >/dev/null
    openssl ecparam -name prime256v1 -genkey -noout -out "$acme/fixture.key" 2>/dev/null
    openssl req -new -key "$acme/fixture.key" -subj /CN=acme-fault-proxy -out "$acme/fixture.csr"
    printf '%s\n' 'subjectAltName=DNS:acme-fault-proxy,DNS:pebble-short,DNS:localhost,IP:127.0.0.1' \
        'extendedKeyUsage=serverAuth' >"$acme/fixture.ext"
    openssl x509 -req -in "$acme/fixture.csr" -CA "$acme/minica.pem" -CAkey "$acme/minica.key" \
        -set_serial "0x$(random_hex 8)" -days 30 -extfile "$acme/fixture.ext" \
        -out "$acme/fixture.pem" 2>/dev/null
    pebble_config test/certs/localhost/cert.pem test/certs/localhost/key.pem 7776000 \
        >"$acme/pebble/pebble.json"
    # Short enough that a certificate is due for renewal as soon as it is issued.
    pebble_config /config/fixture.pem /config/fixture.key 600 >"$acme/pebble-short/pebble.json"
    cp "$acme/fixture.pem" "$acme/fixture.key" "$acme/pebble-short/"
    cp "$acme/fixture.pem" "$acme/fixture.key" "$acme/minica.pem" "$repository/disposable/fault_proxy.py" \
        "$acme/proxy/"

    containers="$containers $name-challtestsrv"
    docker run -d --name "$name-challtestsrv" --network "$network" --network-alias challtestsrv \
        -p 127.0.0.1::8055 "$challtestsrv" -defaultIPv4 "" -defaultIPv6 "" \
        -http01 "" -https01 "" -tlsalpn01 "" -doh "" >/dev/null
    for instance in pebble pebble-short; do
        containers="$containers $name-$instance"
        docker create --name "$name-$instance" --network "$network" --network-alias "$instance" \
            -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 -e PEBBLE_AUTHZREUSE=0 \
            -p 127.0.0.1::14000 -p 127.0.0.1::15000 "$pebble" \
            -config /config/pebble.json -dnsserver challtestsrv:8053 >/dev/null
        docker cp "$acme/$instance" "$name-$instance:/config" >/dev/null
        docker start "$name-$instance" >/dev/null
    done
    containers="$containers $name-acme-fault-proxy"
    docker create --name "$name-acme-fault-proxy" --network "$network" \
        --network-alias acme-fault-proxy -p 127.0.0.1::14000 -p 127.0.0.1::8080 \
        --entrypoint python3 "$image:$release" /fixture/fault_proxy.py \
        --upstream pebble:14000 --cafile /fixture/minica.pem --certificate /fixture/fixture.pem \
        --key /fixture/fixture.key --dns-upstream challtestsrv:8053 >/dev/null
    docker cp "$acme/proxy" "$name-acme-fault-proxy:/fixture" >/dev/null
    docker start "$name-acme-fault-proxy" >/dev/null
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
    name="$image-$release-$$-$(random_hex 4)"
    create_network
    start_fixtures
    containers="$containers $name"
    # Another process can take the port between choosing and publishing it; choose again then.
    port=""
    for _ in 1 2 3 4 5; do
        candidate=${BARECTL_SSH_TEST_PORT:-$(free_port)}
        if docker run -d --privileged --name "$name" --network "$network" \
            -p "127.0.0.1:$candidate:22" "$image:$release" >/dev/null 2>"$work/run.err"; then
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
    # docs/v0.2-qualification.md#environments cites these revisions.
    echo "Disposable server:"
    docker exec "$name" sh -c '. /etc/os-release; echo "$PRETTY_NAME $(uname -m)";
        php=$(dpkg-query -W -f="\${Package}\n" "php[0-9]*-fpm" 2>/dev/null | head -1);
        dpkg-query -W apt dpkg systemd systemd-resolved util-linux sudo sudo-rs needrestart \
            debconf nginx packagekit ubuntu-helper-virt-hwe "$php" 2>/dev/null;
        readlink -f /usr/bin/sudo'
    echo "ACME fixtures: $pebble $challtestsrv, IPv6 ${ipv6_unavailable:-available}"
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
            BARECTL_ACME_TEST_NETWORK="$network" \
            BARECTL_ACME_TEST_ROOT="$acme/minica.pem" \
            BARECTL_ACME_TEST_PEBBLE="$name-pebble" \
            BARECTL_ACME_TEST_PEBBLE_SHORT="$name-pebble-short" \
            BARECTL_ACME_TEST_CHALLTESTSRV="$name-challtestsrv" \
            BARECTL_ACME_TEST_FAULT_PROXY="$name-acme-fault-proxy" \
            BARECTL_ACME_TEST_IPV6_UNAVAILABLE="$ipv6_unavailable" \
            uv run "$@" python manage.py test --tag ssh
    )
    remove_release
    [ -z "${BARECTL_DISPOSABLE_RESULTS:-}" ] ||
        echo "$architecture" >"$BARECTL_DISPOSABLE_RESULTS/$release"
}

for release in $releases; do
    echo "Ubuntu $release:"
    run_release "$release" "$@"
done
