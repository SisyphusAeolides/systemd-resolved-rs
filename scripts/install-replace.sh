#!/usr/bin/env bash
# Transactionally replace the host systemd-resolved service with this build.
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_ROOT="${RESOLVED_RS_STATE_DIR:-/var/lib/systemd-resolved-rs}"
PREFIX="${RESOLVED_RS_PREFIX:-/usr/local}"
PROBE_NAME="${RESOLVED_RS_PROBE_NAME:-example.com}"

BINARY_SOURCE="$ROOT/target/release/systemd-resolved"
RESOLVECTL_SOURCE="$ROOT/target/release/resolvectl"
UNIT_SOURCE="$ROOT/packaging/systemd/systemd-resolved-replacement.service"
SOCKET_SOURCE="$ROOT/packaging/systemd/systemd-resolved-varlink.socket"
MONITOR_SOCKET_SOURCE="$ROOT/packaging/systemd/systemd-resolved-monitor.socket"
BINARY_DESTINATION="$PREFIX/lib/systemd/systemd-resolved-rs"
RESOLVECTL_DESTINATION="$PREFIX/bin/resolvectl-rs"
UNIT_DESTINATION="/etc/systemd/system/systemd-resolved.service"
SOCKET_DESTINATION="/etc/systemd/system/systemd-resolved-varlink.socket"
MONITOR_SOCKET_DESTINATION="/etc/systemd/system/systemd-resolved-monitor.socket"
RESOLV_CONF="/etc/resolv.conf"
CURRENT_STATE="$STATE_ROOT/current"
BACKUP=""
COMMITTED=0

log() {
    printf '[systemd-resolved-rs] %s\n' "$*"
}

fail() {
    printf '[systemd-resolved-rs] ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

capture_path() {
    local path="$1"
    local key="$2"
    if [[ -e "$path" || -L "$path" ]]; then
        printf 'present\n' >"$BACKUP/$key.state"
        cp -a --no-dereference "$path" "$BACKUP/$key"
    else
        printf 'absent\n' >"$BACKUP/$key.state"
    fi
}

restore_path() {
    local path="$1"
    local key="$2"
    local state
    state="$(cat "$BACKUP/$key.state")"
    rm -rf -- "$path"
    if [[ "$state" == "present" ]]; then
        mkdir -p "$(dirname "$path")"
        cp -a --no-dereference "$BACKUP/$key" "$path"
    fi
}

unit_state() {
    local mode="$1"
    local unit="$2"
    systemctl "$mode" "$unit" 2>/dev/null || true
}

restore_enablement() {
    local unit="$1"
    local state_file="$2"
    local state
    state="$(cat "$BACKUP/$state_file")"
    case "$state" in
        enabled|enabled-runtime|linked|linked-runtime|alias)
            systemctl unmask "$unit" >/dev/null 2>&1 || true
            systemctl enable "$unit" >/dev/null 2>&1 || true
            ;;
        disabled)
            systemctl disable "$unit" >/dev/null 2>&1 || true
            ;;
        masked|masked-runtime)
            systemctl mask "$unit" >/dev/null 2>&1 || true
            ;;
    esac
}

restore_activity() {
    local unit="$1"
    local state_file="$2"
    local state
    state="$(cat "$BACKUP/$state_file")"
    case "$state" in
        active|activating|reloading)
            systemctl start "$unit" >/dev/null 2>&1 || true
            ;;
        *)
            systemctl stop "$unit" >/dev/null 2>&1 || true
            ;;
    esac
}

rollback() {
    local reason="${1:-installation failure}"
    [[ -n "$BACKUP" && -d "$BACKUP" ]] || return 0
    log "rolling back: $reason"
    set +e

    systemctl stop systemd-resolved.service systemd-resolved-varlink.socket systemd-resolved-monitor.socket >/dev/null 2>&1

    restore_path "$UNIT_DESTINATION" unit
    restore_path "$SOCKET_DESTINATION" socket
    restore_path "$MONITOR_SOCKET_DESTINATION" monitor-socket
    restore_path "$BINARY_DESTINATION" binary
    restore_path "$RESOLVECTL_DESTINATION" resolvectl
    restore_path "$RESOLV_CONF" resolv-conf

    systemctl daemon-reload >/dev/null 2>&1
    restore_activity systemd-resolved-varlink.socket socket-active
    restore_activity systemd-resolved-monitor.socket monitor-socket-active
    restore_activity systemd-resolved.service service-active
    restore_enablement systemd-resolved-rs.service legacy-enabled
    restore_activity systemd-resolved-rs.service legacy-active
    restore_enablement systemd-resolved-rs.socket legacy-socket-enabled
    restore_activity systemd-resolved-rs.socket legacy-socket-active

    if [[ -L "$CURRENT_STATE" && "$(readlink -f "$CURRENT_STATE" 2>/dev/null)" == "$BACKUP" ]]; then
        rm -f "$CURRENT_STATE"
    fi
    printf '%s\n' "$(date --iso-8601=seconds 2>/dev/null || date)" >"$BACKUP/rolled-back-at"
    set -e
}

on_exit() {
    local status=$?
    if (( status != 0 && COMMITTED == 0 )); then
        rollback "command failed with status $status"
    fi
    exit "$status"
}
trap on_exit EXIT

install_atomic() {
    local source="$1"
    local destination="$2"
    local mode="$3"
    local temporary
    mkdir -p "$(dirname "$destination")"
    temporary="$(mktemp "${destination}.tmp.XXXXXX")"
    install -m "$mode" "$source" "$temporary"
    mv -fT "$temporary" "$destination"
}

install_unit() {
    local temporary
    mkdir -p "$(dirname "$UNIT_DESTINATION")"
    temporary="$(mktemp "${UNIT_DESTINATION}.tmp.XXXXXX")"
    sed "s|@SYSTEMD_RESOLVED_RS@|$BINARY_DESTINATION|g" "$UNIT_SOURCE" >"$temporary"
    chmod 0644 "$temporary"
    mv -fT "$temporary" "$UNIT_DESTINATION"
}

probe_stub() {
    python3 - "$PROBE_NAME" <<'PY'
import random
import socket
import struct
import sys

name = sys.argv[1].strip().rstrip('.')
if not name:
    raise SystemExit('empty probe name')

identifier = random.randrange(1, 65536)
query = bytearray(struct.pack('!HHHHHH', identifier, 0x0100, 1, 0, 0, 0))
for label in name.split('.'):
    encoded = label.encode('idna')
    if not encoded or len(encoded) > 63:
        raise SystemExit('invalid probe name')
    query.append(len(encoded))
    query.extend(encoded)
query.append(0)
query.extend(struct.pack('!HH', 1, 1))
query = bytes(query)


def validate(packet: bytes) -> None:
    if len(packet) < 12:
        raise RuntimeError('short DNS response')
    response_id, flags, qdcount, ancount = struct.unpack_from('!HHHH', packet, 0)
    if response_id != identifier:
        raise RuntimeError('DNS transaction ID mismatch')
    if flags & 0x8000 == 0:
        raise RuntimeError('not a DNS response')
    if flags & 0x000F:
        raise RuntimeError(f'DNS error rcode={flags & 0x000F}')
    if qdcount != 1 or ancount == 0:
        raise RuntimeError('DNS response has no answer')

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.settimeout(5)
    client.sendto(query, ('127.0.0.53', 53))
    response, _ = client.recvfrom(65535)
validate(response)

with socket.create_connection(('127.0.0.53', 53), timeout=5) as client:
    client.settimeout(5)
    client.sendall(struct.pack('!H', len(query)) + query)
    length = client.recv(2)
    if len(length) != 2:
        raise RuntimeError('short DNS-over-TCP length')
    remaining = struct.unpack('!H', length)[0]
    response = bytearray()
    while len(response) < remaining:
        chunk = client.recv(remaining - len(response))
        if not chunk:
            raise RuntimeError('unexpected DNS-over-TCP EOF')
        response.extend(chunk)
validate(bytes(response))
PY
}

switch_resolv_conf() {
    local temporary
    temporary="$(mktemp /etc/.resolv.conf.systemd-resolved-rs.XXXXXX)"
    rm -f "$temporary"
    ln -s /run/systemd/resolve/stub-resolv.conf "$temporary"
    mv -fT "$temporary" "$RESOLV_CONF"
}

wait_for_service() {
    local attempt
    for attempt in {1..100}; do
        if systemctl is-active --quiet systemd-resolved.service \
            && [[ -S /run/systemd/resolve/io.systemd.Resolve ]] \
            && [[ -S /run/systemd/resolve/io.systemd.Resolve.Monitor ]] \
            && [[ -s /run/systemd/resolve/stub-resolv.conf ]]; then
            return 0
        fi
        sleep 0.1
    done
    systemctl --no-pager --full status systemd-resolved.service >&2 || true
    journalctl --no-pager -u systemd-resolved.service -n 100 >&2 || true
    return 1
}

(( EUID == 0 )) || fail "run this script as root"
for command in systemctl install cp mv sed mktemp python3 getent busctl; do
    require_command "$command"
done

[[ -x "$BINARY_SOURCE" ]] || fail "missing release binary: $BINARY_SOURCE"
[[ -x "$RESOLVECTL_SOURCE" ]] || fail "missing release binary: $RESOLVECTL_SOURCE"
[[ -r "$UNIT_SOURCE" ]] || fail "missing replacement unit: $UNIT_SOURCE"
[[ -r "$SOCKET_SOURCE" ]] || fail "missing Varlink socket unit: $SOCKET_SOURCE"
[[ -r "$MONITOR_SOCKET_SOURCE" ]] || fail "missing monitor Varlink socket unit: $MONITOR_SOCKET_SOURCE"
[[ -r "$ROOT/tests/live-dns.py" ]] || fail "missing live resolver test"
getent passwd systemd-resolve >/dev/null || fail "systemd-resolve user does not exist"

if [[ -e "$CURRENT_STATE" || -L "$CURRENT_STATE" ]]; then
    fail "a replacement state is already active; run scripts/uninstall-restore.sh first"
fi

log "running isolated UDP, TCP, proxy, and Varlink preflight"
python3 "$ROOT/tests/live-dns.py" "$BINARY_SOURCE" "$RESOLVECTL_SOURCE"

mkdir -p "$STATE_ROOT/backups"
BACKUP="$STATE_ROOT/backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$BACKUP"
printf '%s\n' "$ROOT" >"$BACKUP/source-root"
printf '%s\n' "$BINARY_DESTINATION" >"$BACKUP/binary-destination"
printf '%s\n' "$RESOLVECTL_DESTINATION" >"$BACKUP/resolvectl-destination"
printf '%s\n' "$UNIT_DESTINATION" >"$BACKUP/unit-destination"
printf '%s\n' "$SOCKET_DESTINATION" >"$BACKUP/socket-destination"
printf '%s\n' "$MONITOR_SOCKET_DESTINATION" >"$BACKUP/monitor-socket-destination"

capture_path "$UNIT_DESTINATION" unit
capture_path "$SOCKET_DESTINATION" socket
capture_path "$MONITOR_SOCKET_DESTINATION" monitor-socket
capture_path "$BINARY_DESTINATION" binary
capture_path "$RESOLVECTL_DESTINATION" resolvectl
capture_path "$RESOLV_CONF" resolv-conf
unit_state is-enabled systemd-resolved.service >"$BACKUP/service-enabled"
unit_state is-active systemd-resolved.service >"$BACKUP/service-active"
unit_state is-enabled systemd-resolved-varlink.socket >"$BACKUP/socket-enabled"
unit_state is-active systemd-resolved-varlink.socket >"$BACKUP/socket-active"
unit_state is-enabled systemd-resolved-monitor.socket >"$BACKUP/monitor-socket-enabled"
unit_state is-active systemd-resolved-monitor.socket >"$BACKUP/monitor-socket-active"
unit_state is-enabled systemd-resolved-rs.service >"$BACKUP/legacy-enabled"
unit_state is-active systemd-resolved-rs.service >"$BACKUP/legacy-active"
unit_state is-enabled systemd-resolved-rs.socket >"$BACKUP/legacy-socket-enabled"
unit_state is-active systemd-resolved-rs.socket >"$BACKUP/legacy-socket-active"

log "installing replacement binary without overwriting distribution files"
install_atomic "$BINARY_SOURCE" "$BINARY_DESTINATION" 0755
install_atomic "$RESOLVECTL_SOURCE" "$RESOLVECTL_DESTINATION" 0755
install_unit
install_atomic "$SOCKET_SOURCE" "$SOCKET_DESTINATION" 0644
install_atomic "$MONITOR_SOCKET_SOURCE" "$MONITOR_SOCKET_DESTINATION" 0644

systemctl disable --now systemd-resolved-rs.service systemd-resolved-rs.socket >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl stop systemd-resolved.service systemd-resolved-varlink.socket systemd-resolved-monitor.socket >/dev/null 2>&1 || true
systemctl start systemd-resolved-varlink.socket
systemctl start systemd-resolved-monitor.socket
systemctl start systemd-resolved.service
wait_for_service

log "verifying D-Bus, Varlink, UDP, and TCP before changing /etc/resolv.conf"
busctl get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    DNSEx >/dev/null
"$RESOLVECTL_DESTINATION" \
    --socket /run/systemd/resolve/io.systemd.Resolve \
    query "$PROBE_NAME" >/dev/null
"$RESOLVECTL_DESTINATION" --socket /run/systemd/resolve/io.systemd.Resolve statistics >/dev/null
"$RESOLVECTL_DESTINATION" --socket /run/systemd/resolve/io.systemd.Resolve show-cache >/dev/null
"$RESOLVECTL_DESTINATION" --socket /run/systemd/resolve/io.systemd.Resolve show-server-state >/dev/null
probe_stub

log "switching /etc/resolv.conf only after direct resolver checks passed"
switch_resolv_conf
getent ahosts "$PROBE_NAME" >/dev/null

mkdir -p "$STATE_ROOT"
ln -s "$BACKUP" "$STATE_ROOT/.current.$$"
mv -fT "$STATE_ROOT/.current.$$" "$CURRENT_STATE"
printf '%s\n' "$(date --iso-8601=seconds 2>/dev/null || date)" >"$BACKUP/installed-at"

COMMITTED=1
trap - EXIT
log "replacement active and verified"
log "rollback state: $BACKUP"
log "restore with: $ROOT/scripts/uninstall-restore.sh"
