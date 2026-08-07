#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
VARLINK_PID=""
DNS_PID=""

cleanup() {
    status=$?
    for pid in "$VARLINK_PID" "$DNS_PID"; do
        if [[ -n "$pid" ]]; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if (( status != 0 )); then
        for log in "$WORK"/*.log; do
            [[ -f "$log" ]] && cat "$log" >&2
        done
    fi
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

export SYSTEMD_NSS_RESOLVE_SHM=0

python3 "$ROOT/tests/fake-varlink-resolve.py" \
    --socket "$WORK/io.systemd.Resolve" \
    --ready-file "$WORK/varlink.ready" \
    >"$WORK/varlink.log" 2>&1 &
VARLINK_PID=$!
for _ in {1..100}; do
    [[ -s "$WORK/varlink.ready" ]] && break
    if ! kill -0 "$VARLINK_PID" 2>/dev/null; then
        cat "$WORK/varlink.log" >&2
        exit 1
    fi
    sleep 0.05
done
[[ -s "$WORK/varlink.ready" ]]

export SYSTEMD_NSS_RESOLVE_VARLINK="$WORK/io.systemd.Resolve"
export SYSTEMD_NSS_RESOLVE_STUB="127.0.0.1:1"
"$ROOT/nss/test_nss"

kill -TERM "$VARLINK_PID"
wait "$VARLINK_PID"
VARLINK_PID=""

python3 "$ROOT/tests/deterministic-dns-server.py" \
    --ready-file "$WORK/dns.port" \
    >"$WORK/dns.log" 2>&1 &
DNS_PID=$!
for _ in {1..100}; do
    [[ -s "$WORK/dns.port" ]] && break
    if ! kill -0 "$DNS_PID" 2>/dev/null; then
        cat "$WORK/dns.log" >&2
        exit 1
    fi
    sleep 0.05
done
[[ -s "$WORK/dns.port" ]]

export SYSTEMD_NSS_RESOLVE_VARLINK=0
export SYSTEMD_NSS_RESOLVE_STUB="127.0.0.1:$(cat "$WORK/dns.port")"
"$ROOT/nss/test_nss"
