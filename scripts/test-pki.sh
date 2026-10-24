#!/usr/bin/env bash
# Writes a throwaway CA and a server certificate for localhost into the given directory.
set -euo pipefail
dir=$1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -subj /CN=lokaj-test-ca -keyout "$dir/ca.key" -out "$dir/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj /CN=localhost -keyout "$dir/server.key" -out "$dir/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$dir/server.ext"
openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -days 2 -extfile "$dir/server.ext" -out "$dir/server.crt" 2>/dev/null
