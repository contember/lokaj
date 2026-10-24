#!/usr/bin/env bash
# Load test against PostgreSQL 18 in Docker, directly and through two lokaj replicas. Run it on
# three SMT pairs reserved for it, e.g. `cpu-lease run -n 6 -- scripts/load.sh`. PostgreSQL gets
# one pair, each replica one thread (one vCPU) of the second, and the load generator the third.
#
# LOKAJ_LOAD_POOLER=pgbouncer runs the same test through two PgBouncer instances instead, with
# the same pool limits, for comparison.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
pooler=${LOKAJ_LOAD_POOLER:-lokaj}
usage="run it on three reserved SMT pairs, e.g. cpu-lease run -n 6 -- $0"

mapfile -t cpus < <(python3 -c '
import os
for cpu in sorted(os.sched_getaffinity(0)):
    print(cpu)
')
pairs=()
for cpu in "${cpus[@]}"; do
    siblings=$(cat "/sys/devices/system/cpu/cpu$cpu/topology/thread_siblings_list")
    [[ " ${pairs[*]} " == *" $siblings "* ]] || pairs+=("$siblings")
done
# Exactly three whole pairs: a wider affinity means the CPUs are shared, and numbers from shared
# CPUs mean nothing.
if ((${#cpus[@]} != 6 || ${#pairs[@]} != 3)); then
    echo "needs exactly three whole SMT pairs, got CPUs ${cpus[*]}; $usage" >&2
    exit 1
fi
pg_cpus=${pairs[0]}
IFS=',-' read -r lokaj_a lokaj_b <<<"${pairs[1]}"
generator_cpus=${pairs[2]}
echo "cpus: postgres $pg_cpus, lokaj $lokaj_a and $lokaj_b, generator $generator_cpus"

work=$(mktemp -d)
container=lokaj-load-$$
pids=()
poolers=()
pooler_pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    docker rm -f "$container" "${poolers[@]}" >/dev/null 2>&1 || true
    docker network rm "$container" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

# The container address, not a published port: docker-proxy would sit in the path, unpinned. It
# is fixed so the server certificate can name it; the poolers verify it.
octet=$((20 + $$ % 200))
pg_host=172.30.$octet.10
pg_port=5432
docker network create --subnet "172.30.$octet.0/24" "$container" >/dev/null
"$root/scripts/test-pki.sh" "$work" "IP:$pg_host"
# TLS on PostgreSQL, which the poolers use and the probe compares with plaintext, so it can tell
# the cost of TLS from the cost of the extra hop. The server key must belong to the postgres user.
docker run -d --name "$container" --network "$container" --ip "$pg_host" \
    --cpuset-cpus "$pg_cpus" --shm-size 1g \
    -v "$work/server.crt:/tls/server.crt:ro" -v "$work/server.key:/tls/server.key:ro" \
    -e POSTGRES_PASSWORD=postgres -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
    -e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 \
    --entrypoint bash postgres:18 -c '
        install -o postgres -m 600 /tls/server.key /tmp/server.key
        exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/server.crt \
            -c ssl_key_file=/tmp/server.key "$@"' postgres \
    -c max_connections=1500 -c shared_buffers=512MB -c fsync=off \
    -c synchronous_commit=off -c full_page_writes=off -c max_wal_size=8GB >/dev/null
# During initdb the entrypoint's temporary server listens on the Unix socket only.
for _ in $(seq 1 120); do
    docker exec "$container" pg_isready -h 127.0.0.1 -U postgres -q 2>/dev/null && break
    sleep 0.5
done

lokaj_ports=()
admin_addresses=()
if [[ $pooler == pgbouncer ]]; then
    # PgBouncer runs as uid 70 in its image; the key is a throwaway test key.
    chmod 755 "$work"
    chmod 644 "$work/server.key"
    printf '"postgres" "postgres"\n' >"$work/userlist.txt"
    for cpu in "$lokaj_a" "$lokaj_b"; do
        port=$(free_port)
        cat >"$work/pgbouncer-$cpu.ini" <<EOF
[databases]
* = host=$pg_host port=$pg_port
[pgbouncer]
listen_addr = 127.0.0.1
listen_port = $port
unix_socket_dir =
pool_mode = transaction
default_pool_size = 10
min_pool_size = 0
max_client_conn = 5000
server_idle_timeout = 60
server_lifetime = 3600
auth_type = scram-sha-256
auth_file = /cfg/userlist.txt
auth_user = postgres
auth_dbname = postgres
auth_query = SELECT usename, passwd FROM pg_shadow WHERE usename = \$1
client_tls_sslmode = require
client_tls_cert_file = /cfg/server.crt
client_tls_key_file = /cfg/server.key
server_tls_sslmode = verify-full
server_tls_ca_file = /cfg/ca.crt
log_connections = 0
log_disconnections = 0
EOF
        name=$container-pgbouncer-$cpu
        docker run -d --name "$name" --network host --cpuset-cpus "$cpu" -v "$work:/cfg:ro" \
            --entrypoint /usr/bin/pgbouncer edoburu/pgbouncer:v1.26.1-p0 "/cfg/pgbouncer-$cpu.ini" >/dev/null
        poolers+=("$name")
        for _ in $(seq 1 50); do
            (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
            sleep 0.1
        done
        pid=$(docker inspect -f '{{if .State.Running}}{{.State.Pid}}{{end}}' "$name")
        if [[ -z $pid ]]; then
            docker logs "$name" >&2
            exit 1
        fi
        # Measured only: the container is removed, not killed by pid.
        pooler_pids+=("$pid")
        lokaj_ports+=("$port")
    done
fi

[[ $pooler == pgbouncer ]] || cargo build --release --quiet --manifest-path "$root/Cargo.toml"
for cpu in "$lokaj_a" "$lokaj_b"; do
    [[ $pooler == pgbouncer ]] && break
    port=$(free_port)
    admin_port=$(free_port)
    cat >"$work/lokaj-$cpu.toml" <<EOF
listen = "127.0.0.1:$port"
admin_listen = "127.0.0.1:$admin_port"
[tls]
cert = "$work/server.crt"
key = "$work/server.key"
[server]
host = "$pg_host"
port = $pg_port
ca = "$work/ca.crt"
EOF
    LOKAJ_LOG=warn taskset -c "$cpu" "$root/target/release/lokaj" "$work/lokaj-$cpu.toml" >"$work/lokaj-$cpu.log" 2>&1 &
    pids+=($!)
    lokaj_ports+=("$port")
    admin_addresses+=("127.0.0.1:$admin_port")
done
for address in "${admin_addresses[@]}"; do
    for _ in $(seq 1 50); do
        curl -sf "http://$address/readyz" >/dev/null && break
        sleep 0.1
    done
done

(cd "$root/tests/node" && npm ci --silent --no-audit --no-fund)
status=0
(IFS=,; cd "$root/tests/node" &&
    LOKAJ_LOAD_PG="$pg_host:$pg_port" LOKAJ_LOAD_LOKAJ="${lokaj_ports[*]}" \
        LOKAJ_LOAD_ADMIN="${admin_addresses[*]}" LOKAJ_LOAD_PIDS="${pids[*]}${pooler_pids[*]}" LOKAJ_LOAD_CA="$work/ca.crt" \
        taskset -c "$generator_cpus" node load.mjs) || status=$?
echo "--- postgres checkpoints"
docker logs "$container" 2>&1 | grep -E 'checkpoint (starting|complete)' || true
for name in "${poolers[@]}"; do
    echo "--- $name"
    docker logs "$name" 2>&1 | grep -v " LOG " | tail -20 || true
done
for log in "$work"/lokaj-*.log; do
    if [[ -s $log ]]; then
        echo "--- $(basename "$log")"
        tail -20 "$log"
    fi
done
exit "$status"
