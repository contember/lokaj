#!/usr/bin/env bash
# Writes a throwaway CA and a server certificate for localhost into the given directory. Further
# arguments are extra subjectAltName entries, e.g. DNS:reader or IP:172.31.20.10.
set -euo pipefail
dir=$1
shift
sans=DNS:localhost,IP:127.0.0.1
for san in "$@"; do sans+=",$san"; done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -subj /CN=lokaj-test-ca -keyout "$dir/ca.key" -out "$dir/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj /CN=localhost -keyout "$dir/server.key" -out "$dir/server.csr" 2>/dev/null
printf 'subjectAltName=%s\n' "$sans" >"$dir/server.ext"
openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -days 2 -extfile "$dir/server.ext" -out "$dir/server.crt" 2>/dev/null
