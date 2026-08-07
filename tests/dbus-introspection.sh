#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$(realpath "${1:-$ROOT/target/release/systemd-resolved}")"
WORK="$(mktemp -d)"
export ROOT BINARY WORK
trap 'rm -rf "$WORK"' EXIT

for command in busctl dbus-run-session python3; do
    command -v "$command" >/dev/null
done

dbus-run-session --config-file="$ROOT/tests/dbus-test-session.conf" -- bash -euo pipefail <<'ENDSCRIPT'
BINARY="$BINARY"
WORK="$WORK"
ROOT="$ROOT"

export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"
export RESOLVED_RS_STUB_ADDR="127.0.0.1:10531"
export RESOLVED_RS_STUB_ADDR_ALT="127.0.0.1:10532"
export RESOLVED_RS_RUN_DIR="$WORK/runtime"

python3 "$ROOT/tests/deterministic-dns-server.py" \
    --ready-file "$WORK/upstream.port" \
    >"$WORK/upstream.log" 2>&1 &
upstream_pid=$!

for _ in {1..100}; do
    test -s "$WORK/upstream.port" && break
    if ! kill -0 "$upstream_pid" 2>/dev/null; then
        cat "$WORK/upstream.log"
        exit 1
    fi
    sleep 0.1
done
test -s "$WORK/upstream.port"
upstream_port="$(cat "$WORK/upstream.port")"

"$BINARY" --upstream "127.0.0.1:$upstream_port" >"$WORK/daemon.log" 2>&1 &
daemon_pid=$!

cleanup() {
    status=$?
    kill -TERM "$daemon_pid" "$upstream_pid" 2>/dev/null || true
    for _ in {1..50}; do
        if ! kill -0 "$daemon_pid" 2>/dev/null && ! kill -0 "$upstream_pid" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    kill -KILL "$daemon_pid" "$upstream_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    wait "$upstream_pid" 2>/dev/null || true
    if (( status != 0 )); then
        cat "$WORK/daemon.log"
        cat "$WORK/upstream.log"
    fi
    exit "$status"
}
trap cleanup EXIT

ready=false
for _ in {1..100}; do
    if busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" --no-pager --xml-interface introspect \
        org.freedesktop.resolve1 \
        /org/freedesktop/resolve1 \
        org.freedesktop.resolve1.Manager \
        >"$WORK/manager.xml" 2>/dev/null; then
        ready=true
        break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
        cat "$WORK/daemon.log"
        exit 1
    fi
    sleep 0.1
done
test "$ready" = true

python3 "$ROOT/tests/compare-dbus-introspection.py" \
    "$ROOT/compat/org.freedesktop.resolve1.Manager.xml" \
    "$WORK/manager.xml" \
    org.freedesktop.resolve1.Manager

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    ResolveHostname \
    'isit' \
    0 example.test 2 0 \
    >"$WORK/resolve-hostname.txt"
grep -F '192 0 2 123' "$WORK/resolve-hostname.txt" >/dev/null
grep -F 'example.test' "$WORK/resolve-hostname.txt" >/dev/null

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    ResolvConfMode \
    >"$WORK/resolv-conf-mode.txt"
grep -F 'foreign' "$WORK/resolv-conf-mode.txt" >/dev/null

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    SetLinkDomains \
    'ia(sb)' \
    1 1 example.test false \
    >/dev/null

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    SetLinkDNS \
    'ia(iay)' \
    1 1 2 4 192 0 2 53 \
    >/dev/null

ready=false
for _ in {1..100}; do
    if busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" --no-pager --xml-interface introspect \
        org.freedesktop.resolve1 \
        /org/freedesktop/resolve1/link/_31 \
        org.freedesktop.resolve1.Link \
        >"$WORK/link.xml" 2>/dev/null; then
        ready=true
        break
    fi
    sleep 0.1
done
test "$ready" = true

python3 "$ROOT/tests/compare-dbus-introspection.py" \
    "$ROOT/compat/org.freedesktop.resolve1.Link.xml" \
    "$WORK/link.xml" \
    org.freedesktop.resolve1.Link

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    Domains \
    >"$WORK/link-domains.txt"
grep -F 'example.test' "$WORK/link-domains.txt" >/dev/null

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    DNS \
    >"$WORK/link-dns.txt"
grep -F '192 0 2 53' "$WORK/link-dns.txt" >/dev/null
ENDSCRIPT
