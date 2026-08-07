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

"$BINARY" >"$WORK/daemon.log" 2>&1 &
daemon_pid=$!

cleanup() {
    status=$?
    kill -TERM "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    if (( status != 0 )); then
        cat "$WORK/daemon.log"
    fi
    exit "$status"
}
trap cleanup EXIT

ready=false
for _ in $(seq 1 100); do
    if busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" --no-pager --xml-interface introspect org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager >"$WORK/manager.xml" 2>/dev/null; then
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

python3 "$ROOT/tests/compare-dbus-introspection.py" "$ROOT/compat/org.freedesktop.resolve1.Manager.xml" "$WORK/manager.xml" org.freedesktop.resolve1.Manager

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDomains 'ia(sb)' 1 1 example.test false >/dev/null

ready=false
for _ in $(seq 1 100); do
    if busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" --no-pager --xml-interface introspect org.freedesktop.resolve1 /org/freedesktop/resolve1/link/_31 org.freedesktop.resolve1.Link >"$WORK/link.xml" 2>/dev/null; then
        ready=true
        break
    fi
    sleep 0.1
done
test "$ready" = true

python3 "$ROOT/tests/compare-dbus-introspection.py" "$ROOT/compat/org.freedesktop.resolve1.Link.xml" "$WORK/link.xml" org.freedesktop.resolve1.Link
ENDSCRIPT
