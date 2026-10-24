#!/usr/bin/env bash
# Integration tests against PostgreSQL 18 in Docker: the Rust protocol suite (lokaj in-process)
# and the node-pg suite (the lokaj binary). Pass `rust` or `node` to run only one of them.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
suites=${1:-all}
image=${LOKAJ_TEST_IMAGE:-postgres:18}
container=lokaj-it-$$
work=$(mktemp -d)
lokaj_pid=

cleanup() {
    [[ -n $lokaj_pid ]] && kill "$lokaj_pid" 2>/dev/null || true
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

"$root/scripts/test-pki.sh" "$work"
# Roles other than the test superuser may connect over TLS only, so a server connection lokaj
# opened without TLS would fail. Members of `refused` are turned away before authentication.
# The server key must belong to the postgres user.
printf '%s\n' 'local all all trust' 'hostssl all +refused all reject' 'hostssl all all all scram-sha-256' \
    'host all postgres all scram-sha-256' 'host all all all reject' >"$work/pg_hba.conf"
docker run -d --name "$container" \
    -v "$work/server.crt:/tls/server.crt:ro" -v "$work/server.key:/tls/server.key:ro" \
    -v "$work/pg_hba.conf:/tls/pg_hba.conf:ro" \
    -e POSTGRES_PASSWORD=postgres \
    -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
    -e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 \
    -p 127.0.0.1::5432 \
    --entrypoint bash "$image" -c '
        install -o postgres -m 600 /tls/server.key /tmp/server.key
        exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/server.crt \
            -c ssl_key_file=/tmp/server.key -c hba_file=/tls/pg_hba.conf "$@"' postgres \
    -c max_connections=1000 >/dev/null
port=$(docker port "$container" 5432/tcp | head -1 | sed 's/.*://')
# During initdb the entrypoint's temporary server listens on the Unix socket only.
for _ in $(seq 1 120); do
    docker exec "$container" pg_isready -h 127.0.0.1 -U postgres -q 2>/dev/null && break
    sleep 0.5
done
export LOKAJ_TEST_PG=127.0.0.1:$port
export LOKAJ_TEST_PG_CA=$work/ca.crt
echo "PostgreSQL at $LOKAJ_TEST_PG"

if [[ $suites == all || $suites == rust ]]; then
    (cd "$root" && cargo test --test integration -- --test-threads=8)
fi

if [[ $suites == all || $suites == node ]]; then
    (cd "$root" && cargo build --release --quiet)
    listen_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
    admin_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
    cat >"$work/lokaj.toml" <<EOF
listen = "127.0.0.1:$listen_port"
admin_listen = "127.0.0.1:$admin_port"
[tls]
cert = "$work/server.crt"
key = "$work/server.key"
[server]
host = "127.0.0.1"
port = $port
ca = "$work/ca.crt"
[pool]
max_size = 5
EOF
    LOKAJ_LOG=${LOKAJ_LOG:-warn} "$root/target/release/lokaj" "$work/lokaj.toml" &
    lokaj_pid=$!
    for _ in $(seq 1 50); do
        curl -fs "http://127.0.0.1:$admin_port/readyz" >/dev/null && break
        sleep 0.1
    done
    (cd "$root/tests/node" && npm ci --silent --no-audit --no-fund &&
        LOKAJ_TEST_LOKAJ=127.0.0.1:$listen_port LOKAJ_TEST_ADMIN=127.0.0.1:$admin_port \
            LOKAJ_TEST_CA=$work/ca.crt node --test --test-concurrency=4 ./*.test.mjs)
fi
