#!/usr/bin/env bash
# Chaos scenarios (reader reboot, fallback to the writer and back, pooler kill, drain) against a
# primary and a hot standby in Docker. Builds the lokaj image first.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

docker build -q -t lokaj:chaos "$root" >/dev/null
"$root/scripts/test-pki.sh" "$work"
# The image runs as an unprivileged user.
chmod 644 "$work/server.key"
chmod 755 "$work"
touch "$work/hosts"
(cd "$root/tests/node" && npm ci --silent --no-audit --no-fund &&
    LOKAJ_CHAOS_IMAGE=lokaj:chaos LOKAJ_CHAOS_PKI=$work node chaos.mjs)
