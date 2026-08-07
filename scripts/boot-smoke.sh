#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROBE_NAME="${RESOLVED_RS_PROBE_NAME:-example.com}"
EXPECTED_BINARY="${RESOLVED_RS_EXPECTED_BINARY:-/usr/local/lib/systemd/systemd-resolved-rs}"
RESOLVECTL_RS="${RESOLVED_RS_RESOLVECTL:-/usr/local/bin/resolvectl-rs}"
FAILURES=0

check() {
    local name="$1"
    shift
    if "$@"; then
        printf 'OK   %s\n' "$name"
    else
        printf 'FAIL %s\n' "$name" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

replacement_binary_active() {
    systemctl show \
        --property=ExecStart \
        --value \
        systemd-resolved.service \
        | grep -F -- "$EXPECTED_BINARY" >/dev/null
}

resolv_conf_is_stub() {
    [[ "$(readlink -f /etc/resolv.conf)" == "/run/systemd/resolve/stub-resolv.conf" ]]
}

varlink_query() {
    [[ -x "$RESOLVECTL_RS" ]]
    "$RESOLVECTL_RS" \
        --socket /run/systemd/resolve/io.systemd.Resolve \
        query "$PROBE_NAME" >/dev/null
}

stock_resolvectl_query() {
    command -v resolvectl >/dev/null 2>&1
    resolvectl query "$PROBE_NAME" >/dev/null
}

check service-active systemctl is-active --quiet systemd-resolved.service
check replacement-binary replacement_binary_active
check varlink-socket test -S /run/systemd/resolve/io.systemd.Resolve
check stub-resolv-conf test -s /run/systemd/resolve/stub-resolv.conf
check uplink-resolv-conf test -s /run/systemd/resolve/resolv.conf
check resolv-conf-link resolv_conf_is_stub
check dbus-manager busctl get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    DNSEx
check udp-and-tcp-stub python3 "$ROOT/scripts/probe-stub.py" "$PROBE_NAME"
check varlink-query varlink_query
check stock-resolvectl stock_resolvectl_query
check nss-getent getent ahosts "$PROBE_NAME"
check localhost getent ahosts localhost

if (( FAILURES != 0 )); then
    systemctl --no-pager --full status systemd-resolved.service >&2 || true
    journalctl --no-pager -u systemd-resolved.service -n 100 >&2 || true
fi

exit "$FAILURES"
