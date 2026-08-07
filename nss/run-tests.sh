#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
    status=$?
    if [[ -n "$SERVER_PID" ]]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if (( status != 0 )) && [[ -f "$WORK/server.log" ]]; then
        cat "$WORK/server.log" >&2
    fi
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

python3 "$ROOT/tests/deterministic-dns-server.py" \
    --ready-file "$WORK/port" \
    >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

for _ in {1..100}; do
    [[ -s "$WORK/port" ]] && break
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        cat "$WORK/server.log" >&2
        exit 1
    fi
    sleep 0.05
done
[[ -s "$WORK/port" ]]

export SYSTEMD_NSS_RESOLVE_STUB="127.0.0.1:$(cat "$WORK/port")"
"$ROOT/nss/test_nss"
