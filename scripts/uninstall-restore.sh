#!/usr/bin/env bash
# Restore the exact host state captured by install-replace.sh.
set -Eeuo pipefail
umask 077

STATE_ROOT="${RESOLVED_RS_STATE_DIR:-/var/lib/systemd-resolved-rs}"
CURRENT_STATE="$STATE_ROOT/current"

log() {
    printf '[systemd-resolved-rs] %s\n' "$*"
}

fail() {
    printf '[systemd-resolved-rs] ERROR: %s\n' "$*" >&2
    exit 1
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

verify_activity() {
    local unit="$1"
    local state_file="$2"
    local state
    state="$(cat "$BACKUP/$state_file")"
    case "$state" in
        active|activating|reloading)
            systemctl is-active --quiet "$unit" \
                || fail "failed to restore active state for $unit"
            ;;
        *)
            if systemctl is-active --quiet "$unit"; then
                fail "failed to restore inactive state for $unit"
            fi
            ;;
    esac
}

verify_path() {
    local path="$1"
    local key="$2"
    local state
    state="$(cat "$BACKUP/$key.state")"
    if [[ "$state" == "present" ]]; then
        [[ -e "$path" || -L "$path" ]] || fail "failed to restore $path"
    else
        [[ ! -e "$path" && ! -L "$path" ]] || fail "failed to remove $path"
    fi
}

(( EUID == 0 )) || fail "run this script as root"
[[ -L "$CURRENT_STATE" ]] || fail "no active replacement state exists"
BACKUP="$(readlink -f "$CURRENT_STATE")"
[[ -d "$BACKUP" && "$BACKUP" == "$STATE_ROOT"/backups/* ]] \
    || fail "invalid replacement state: $BACKUP"

BINARY_DESTINATION="$(cat "$BACKUP/binary-destination")"
RESOLVECTL_DESTINATION="$(cat "$BACKUP/resolvectl-destination")"
UNIT_DESTINATION="$(cat "$BACKUP/unit-destination")"
SOCKET_DESTINATION="$(cat "$BACKUP/socket-destination")"

log "stopping replacement resolver"
systemctl stop systemd-resolved.service systemd-resolved-varlink.socket >/dev/null 2>&1 || true

restore_path "$UNIT_DESTINATION" unit
restore_path "$SOCKET_DESTINATION" socket
restore_path "$BINARY_DESTINATION" binary
restore_path "$RESOLVECTL_DESTINATION" resolvectl
restore_path /etc/resolv.conf resolv-conf

systemctl daemon-reload
restore_enablement systemd-resolved.service service-enabled
restore_enablement systemd-resolved-varlink.socket socket-enabled
restore_activity systemd-resolved-varlink.socket socket-active
restore_activity systemd-resolved.service service-active
restore_enablement systemd-resolved-rs.service legacy-enabled
restore_activity systemd-resolved-rs.service legacy-active
restore_enablement systemd-resolved-rs.socket legacy-socket-enabled
restore_activity systemd-resolved-rs.socket legacy-socket-active

verify_path /etc/resolv.conf resolv-conf
verify_activity systemd-resolved-varlink.socket socket-active
verify_activity systemd-resolved.service service-active
verify_activity systemd-resolved-rs.socket legacy-socket-active
verify_activity systemd-resolved-rs.service legacy-active

rm -f "$CURRENT_STATE"
printf '%s\n' "$(date --iso-8601=seconds 2>/dev/null || date)" >"$BACKUP/restored-at"
log "restored the captured resolver, unit, binary, and /etc/resolv.conf state"
log "preserved audit record: $BACKUP"
