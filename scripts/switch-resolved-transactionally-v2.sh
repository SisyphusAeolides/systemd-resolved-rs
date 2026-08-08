#!/usr/bin/env bash
set -euo pipefail

STATE_ROOT=/var/lib/systemd-resolved-rs
SYSTEM_COPY=/usr/lib/systemd/systemd-resolved-rs-switch
GUARD_UNIT=/etc/systemd/system/systemd-resolved-rs-guard.service
GUARD_NAME=systemd-resolved-rs-guard.service
DROPIN_DIR=/etc/systemd/system/systemd-resolved.service.d
DROPIN_PATH=$DROPIN_DIR/90-systemd-resolved-rs.conf
ACTIVE_LINK=$STATE_ROOT/active
MODE=install
CERTIFICATE=
TRANSACTION=
EXTERNAL_NAME=
MAX_CERTIFICATE_AGE=86400

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/switch-resolved-transactionally.sh --certificate FILE [OPTIONS]
  sudo scripts/switch-resolved-transactionally.sh --confirm TRANSACTION
  sudo scripts/switch-resolved-transactionally.sh --rollback [TRANSACTION]
  sudo /usr/lib/systemd/systemd-resolved-rs-switch --guard

Install mode requires a schema-2 fail-closed certificate whose every gate passed
and whose daemon/client hashes match. The distro package remains installed. Only
a systemd ExecStart drop-in changes, and any failed health check restores the
exact prior drop-in, mask/enable state, guard unit, and active state.

Options:
  --certificate FILE       Certified report from certify-replacement.sh
  --external-name NAME     Optional external DNS name for health checks
  --max-certificate-age S  Maximum certificate age in seconds (default 86400)
  --confirm TRANSACTION    Confirm after a healthy reboot
  --rollback [TRANSACTION] Restore selected or active transaction
  --guard                  Internal boot-guard mode
  -h, --help               Show this help
EOF
}

while (($#)); do
    case "$1" in
        --certificate)
            MODE=install
            CERTIFICATE=${2:?missing certificate path}
            shift 2
            ;;
        --external-name)
            EXTERNAL_NAME=${2:?missing external DNS name}
            shift 2
            ;;
        --max-certificate-age)
            MAX_CERTIFICATE_AGE=${2:?missing certificate age}
            shift 2
            ;;
        --confirm)
            MODE=confirm
            TRANSACTION=${2:?missing transaction id}
            shift 2
            ;;
        --rollback)
            MODE=rollback
            if (($# > 1)) && [[ ${2:-} != --* ]]; then
                TRANSACTION=$2
                shift 2
            else
                shift
            fi
            ;;
        --guard)
            MODE=guard
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    printf 'This operation must run as root.\n' >&2
    exit 2
}
[[ $MAX_CERTIFICATE_AGE =~ ^[1-9][0-9]*$ ]] || {
    printf 'Certificate age must be a positive integer.\n' >&2
    exit 2
}

for command in busctl cmp flock getent install python3 readlink sha256sum systemctl; do
    command -v "$command" >/dev/null || {
        printf 'Required command is missing: %s\n' "$command" >&2
        exit 2
    }
done

install -d -m 0700 "$STATE_ROOT" "$STATE_ROOT/transactions"
exec 9>"$STATE_ROOT/transaction.lock"
flock -x 9

active_transaction() {
    if [[ -L $ACTIVE_LINK ]]; then
        basename "$(readlink -f "$ACTIVE_LINK")"
    fi
}

metadata_value() {
    local metadata=$1
    local key=$2
    python3 - "$metadata" "$key" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
value = data
for component in sys.argv[2].split('.'):
    value = value.get(component) if isinstance(value, dict) else None
    if value is None:
        break
if isinstance(value, bool):
    print("true" if value else "false")
elif value is not None:
    print(value)
PY
}

unit_state() {
    local property=$1
    systemctl show --property "$property" --value systemd-resolved.service 2>/dev/null || true
}

restore_enable_state() {
    local state=$1
    systemctl unmask systemd-resolved.service >/dev/null 2>&1 || true
    case "$state" in
        masked)
            systemctl mask systemd-resolved.service >/dev/null
            ;;
        masked-runtime)
            systemctl mask --runtime systemd-resolved.service >/dev/null
            ;;
        enabled)
            systemctl enable systemd-resolved.service >/dev/null 2>&1 || true
            ;;
        enabled-runtime)
            systemctl enable --runtime systemd-resolved.service >/dev/null 2>&1 || true
            ;;
        disabled)
            systemctl disable systemd-resolved.service >/dev/null 2>&1 || true
            ;;
        static|indirect|generated|transient|alias|linked|linked-runtime|bad|not-found|"")
            ;;
        *)
            printf 'Warning: unrecognized previous unit-file state %s\n' "$state" >&2
            ;;
    esac
}

restore_active_state() {
    local state=$1
    case "$state" in
        active|activating|reloading)
            systemctl restart systemd-resolved.service
            ;;
        inactive|deactivating|failed|unknown|"")
            systemctl stop systemd-resolved.service >/dev/null 2>&1 || true
            if [[ $state == failed ]]; then
                systemctl reset-failed systemd-resolved.service >/dev/null 2>&1 || true
            fi
            ;;
        *)
            systemctl restart systemd-resolved.service
            ;;
    esac
}

restore_guard() {
    local directory=$1
    systemctl disable --now "$GUARD_NAME" >/dev/null 2>&1 || true
    rm -f "$GUARD_UNIT"
    if [[ -e $directory/guard.existed ]]; then
        cp -a --no-dereference "$directory/guard.previous" "$GUARD_UNIT"
    fi
    systemctl daemon-reload
    local guard_enabled guard_active
    guard_enabled=$(cat "$directory/guard-enabled.before" 2>/dev/null || true)
    guard_active=$(cat "$directory/guard-active.before" 2>/dev/null || true)
    case "$guard_enabled" in
        enabled) systemctl enable "$GUARD_NAME" >/dev/null 2>&1 || true ;;
        enabled-runtime) systemctl enable --runtime "$GUARD_NAME" >/dev/null 2>&1 || true ;;
        disabled) systemctl disable "$GUARD_NAME" >/dev/null 2>&1 || true ;;
        masked) systemctl mask "$GUARD_NAME" >/dev/null 2>&1 || true ;;
        masked-runtime) systemctl mask --runtime "$GUARD_NAME" >/dev/null 2>&1 || true ;;
        *) ;;
    esac
    if [[ $guard_active == active ]]; then
        systemctl start "$GUARD_NAME" >/dev/null 2>&1 || true
    fi
}

health_check() {
    local transaction=$1
    local directory="$STATE_ROOT/transactions/$transaction"
    local metadata="$directory/transaction.json"
    [[ -s $metadata ]] || return 1

    local binary client external expected_binary pid
    binary=$(metadata_value "$metadata" installed_binary)
    client=$(metadata_value "$metadata" installed_client)
    external=$(metadata_value "$metadata" external_name)
    [[ -x $binary && -x $client ]] || return 1

    local expected_daemon_hash expected_client_hash
    expected_daemon_hash=$(metadata_value "$metadata" daemon_sha256)
    expected_client_hash=$(metadata_value "$metadata" client_sha256)
    [[ $(sha256sum "$binary" | awk '{print $1}') == "$expected_daemon_hash" ]] || return 1
    [[ $(sha256sum "$client" | awk '{print $1}') == "$expected_client_hash" ]] || return 1

    systemctl is-active --quiet systemd-resolved.service || return 1
    pid=$(unit_state MainPID)
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    expected_binary=$(readlink -f "/proc/$pid/exe") || return 1
    [[ $expected_binary == "$(readlink -f "$binary")" ]] || return 1

    python3 - <<'PY' || return 1
import socket
import struct

name = b"\x09localhost\0"
query = struct.pack("!HHHHHH", 0x5253, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
    stream.settimeout(2)
    stream.sendto(query, ("127.0.0.53", 53))
    response, _ = stream.recvfrom(65535)
    if len(response) < 12 or response[:2] != b"RS" or response[3] & 0x0F:
        raise SystemExit(1)
with socket.create_connection(("127.0.0.53", 53), timeout=2) as stream:
    stream.sendall(struct.pack("!H", len(query)) + query)
    length_data = b""
    while len(length_data) < 2:
        chunk = stream.recv(2 - len(length_data))
        if not chunk:
            raise SystemExit(1)
        length_data += chunk
    length = struct.unpack("!H", length_data)[0]
    response = b""
    while len(response) < length:
        chunk = stream.recv(length - len(response))
        if not chunk:
            raise SystemExit(1)
        response += chunk
    if response[:2] != b"RS" or response[3] & 0x0F:
        raise SystemExit(1)
PY

    busctl --system --no-pager introspect \
        org.freedesktop.resolve1 /org/freedesktop/resolve1 \
        org.freedesktop.resolve1.Manager >/dev/null || return 1
    "$client" status >/dev/null || return 1
    "$client" statistics >/dev/null || return 1
    "$client" query localhost >/dev/null || return 1
    getent ahosts localhost >/dev/null || return 1
    if [[ -n $external ]]; then
        "$client" query "$external" >/dev/null || return 1
        getent ahosts "$external" >/dev/null || return 1
    fi
    return 0
}

restore_transaction() {
    local transaction=$1
    local directory="$STATE_ROOT/transactions/$transaction"
    local metadata="$directory/transaction.json"
    [[ -d $directory && -s $metadata ]] || {
        printf 'Unknown transaction: %s\n' "$transaction" >&2
        return 1
    }

    rm -f "$DROPIN_PATH"
    if [[ -e $directory/dropin.existed ]]; then
        install -d -m 0755 "$DROPIN_DIR"
        cp -a --no-dereference "$directory/dropin.previous" "$DROPIN_PATH"
    else
        rmdir "$DROPIN_DIR" 2>/dev/null || true
    fi

    restore_guard "$directory"
    systemctl daemon-reload
    local enabled active
    enabled=$(cat "$directory/resolved-enabled.before" 2>/dev/null || true)
    active=$(cat "$directory/resolved-active.before" 2>/dev/null || true)
    restore_enable_state "$enabled"
    if [[ $enabled == masked || $enabled == masked-runtime ]]; then
        systemctl unmask systemd-resolved.service >/dev/null 2>&1 || true
        restore_active_state "$active"
        restore_enable_state "$enabled"
    else
        restore_active_state "$active"
    fi

    rm -f "$directory/pending"
    printf '%s\n' "$(date --utc --iso-8601=seconds)" >"$directory/rolled-back-at"
    local parent
    parent=$(metadata_value "$metadata" parent_transaction)
    if [[ -n $parent && -d $STATE_ROOT/transactions/$parent ]]; then
        ln -sfn "$STATE_ROOT/transactions/$parent" "$ACTIVE_LINK"
    elif [[ -L $ACTIVE_LINK ]] && [[ $(active_transaction) == "$transaction" ]]; then
        rm -f "$ACTIVE_LINK"
    fi
    printf 'Rolled back resolver transaction %s.\n' "$transaction"
}

case "$MODE" in
    guard)
        TRANSACTION=$(active_transaction || true)
        [[ -n $TRANSACTION ]] || exit 0
        directory="$STATE_ROOT/transactions/$TRANSACTION"
        [[ -e $directory/pending ]] || exit 0
        if health_check "$TRANSACTION"; then
            printf 'Resolver transaction %s passed the boot guard.\n' "$TRANSACTION"
            exit 0
        fi
        printf 'Resolver transaction %s failed the boot guard; rolling back.\n' "$TRANSACTION" >&2
        restore_transaction "$TRANSACTION"
        exit 1
        ;;
    confirm)
        directory="$STATE_ROOT/transactions/$TRANSACTION"
        [[ -e $directory/pending ]] || {
            printf 'Transaction is not pending: %s\n' "$TRANSACTION" >&2
            exit 2
        }
        health_check "$TRANSACTION" || {
            printf 'Transaction is not healthy and cannot be confirmed.\n' >&2
            exit 1
        }
        rm -f "$directory/pending"
        printf '%s\n' "$(date --utc --iso-8601=seconds)" >"$directory/confirmed-at"
        restore_guard "$directory"
        printf 'Confirmed resolver transaction %s.\n' "$TRANSACTION"
        exit 0
        ;;
    rollback)
        if [[ -z $TRANSACTION ]]; then
            TRANSACTION=$(active_transaction || true)
        fi
        [[ -n $TRANSACTION ]] || {
            printf 'There is no active resolver transaction.\n' >&2
            exit 2
        }
        restore_transaction "$TRANSACTION"
        exit 0
        ;;
    install)
        ;;
    *)
        printf 'Invalid mode: %s\n' "$MODE" >&2
        exit 2
        ;;
esac

[[ -n $CERTIFICATE && -s $CERTIFICATE ]] || {
    printf 'A nonempty --certificate file is required.\n' >&2
    exit 2
}
CERTIFICATE=$(readlink -f "$CERTIFICATE")

certificate_output=$(python3 - "$CERTIFICATE" "$MAX_CERTIFICATE_AGE" <<'PY'
from datetime import datetime, timezone
import json
import sys

path = sys.argv[1]
maximum_age = int(sys.argv[2])
data = json.load(open(path, encoding="utf-8"))
if data.get("schema") != 2:
    raise SystemExit("unsupported certificate schema")
if data.get("certified") is not True:
    raise SystemExit("certificate is not certified")
gates = data.get("gates")
if not isinstance(gates, list) or not gates:
    raise SystemExit("certificate contains no gates")
if any(gate.get("status") != "pass" for gate in gates):
    raise SystemExit("certificate contains a nonpassing gate")
generated = datetime.fromisoformat(data["generated_at"])
if generated.tzinfo is None:
    raise SystemExit("certificate timestamp has no timezone")
age = (datetime.now(timezone.utc) - generated.astimezone(timezone.utc)).total_seconds()
if age < -300 or age > maximum_age:
    raise SystemExit(f"certificate age {age:.0f}s is outside the allowed window")
print(data["source_commit"])
print(data["source_tree"])
print(data["binary"]["path"])
print(data["binary"]["sha256"])
print(data["client"]["path"])
print(data["client"]["sha256"])
print(data.get("upstream_commit") or "")
PY
) || {
    printf 'Certificate validation failed.\n' >&2
    exit 1
}
mapfile -t certificate_values <<<"$certificate_output"
[[ ${#certificate_values[@]} -eq 7 ]] || {
    printf 'Certificate validation returned incomplete data.\n' >&2
    exit 1
}

SOURCE_COMMIT=${certificate_values[0]}
SOURCE_TREE=${certificate_values[1]}
BINARY=${certificate_values[2]}
BINARY_SHA256=${certificate_values[3]}
CLIENT=${certificate_values[4]}
CLIENT_SHA256=${certificate_values[5]}
UPSTREAM_COMMIT=${certificate_values[6]}

[[ -x $BINARY && -x $CLIENT ]] || {
    printf 'Certified binaries are missing or not executable.\n' >&2
    exit 1
}
[[ $(sha256sum "$BINARY" | awk '{print $1}') == "$BINARY_SHA256" ]] || {
    printf 'Certified daemon hash does not match.\n' >&2
    exit 1
}
[[ $(sha256sum "$CLIENT" | awk '{print $1}') == "$CLIENT_SHA256" ]] || {
    printf 'Certified client hash does not match.\n' >&2
    exit 1
}

PARENT_TRANSACTION=$(active_transaction || true)
TRANSACTION="$(date --utc +%Y%m%dT%H%M%S)-$$-${SOURCE_COMMIT:0:12}"
DIRECTORY="$STATE_ROOT/transactions/$TRANSACTION"
INSTALL_ROOT="/usr/lib/systemd/systemd-resolved-rs/$SOURCE_COMMIT"
INSTALLED_BINARY="$INSTALL_ROOT/systemd-resolved"
INSTALLED_CLIENT="$INSTALL_ROOT/resolvectl"
install -d -m 0700 "$DIRECTORY"
install -d -m 0755 "$INSTALL_ROOT"
install -m 0755 "$BINARY" "$INSTALLED_BINARY"
install -m 0755 "$CLIENT" "$INSTALLED_CLIENT"
install -m 0755 "$0" "$SYSTEM_COPY"
cp -a "$CERTIFICATE" "$DIRECTORY/certificate.json"

[[ $(sha256sum "$INSTALLED_BINARY" | awk '{print $1}') == "$BINARY_SHA256" ]] || exit 1
[[ $(sha256sum "$INSTALLED_CLIENT" | awk '{print $1}') == "$CLIENT_SHA256" ]] || exit 1

if [[ -e $DROPIN_PATH || -L $DROPIN_PATH ]]; then
    cp -a --no-dereference "$DROPIN_PATH" "$DIRECTORY/dropin.previous"
    : >"$DIRECTORY/dropin.existed"
fi
if [[ -e $GUARD_UNIT || -L $GUARD_UNIT ]]; then
    cp -a --no-dereference "$GUARD_UNIT" "$DIRECTORY/guard.previous"
    : >"$DIRECTORY/guard.existed"
fi
systemctl is-enabled systemd-resolved.service 2>/dev/null \
    >"$DIRECTORY/resolved-enabled.before" || true
systemctl is-active systemd-resolved.service 2>/dev/null \
    >"$DIRECTORY/resolved-active.before" || true
systemctl is-enabled "$GUARD_NAME" 2>/dev/null \
    >"$DIRECTORY/guard-enabled.before" || true
systemctl is-active "$GUARD_NAME" 2>/dev/null \
    >"$DIRECTORY/guard-active.before" || true
systemctl cat systemd-resolved.service >"$DIRECTORY/unit-before.txt" 2>&1 || true
systemctl show systemd-resolved.service >"$DIRECTORY/unit-properties-before.txt" 2>&1 || true
cp -a --no-dereference /etc/resolv.conf "$DIRECTORY/resolv.conf.before" 2>/dev/null || true
cp -a --no-dereference /etc/nsswitch.conf "$DIRECTORY/nsswitch.conf.before" 2>/dev/null || true

python3 - \
    "$DIRECTORY/transaction.json" "$TRANSACTION" "$PARENT_TRANSACTION" \
    "$SOURCE_COMMIT" "$SOURCE_TREE" "$UPSTREAM_COMMIT" "$CERTIFICATE" \
    "$INSTALLED_BINARY" "$BINARY_SHA256" "$INSTALLED_CLIENT" "$CLIENT_SHA256" \
    "$EXTERNAL_NAME" <<'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

(
    path,
    transaction,
    parent,
    source_commit,
    source_tree,
    upstream,
    certificate,
    binary,
    daemon_hash,
    client,
    client_hash,
    external,
) = sys.argv[1:]
Path(path).write_text(
    json.dumps(
        {
            "schema": 2,
            "transaction": transaction,
            "parent_transaction": parent or None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_commit": source_commit,
            "source_tree": source_tree,
            "upstream_commit": upstream,
            "certificate": certificate,
            "installed_binary": binary,
            "daemon_sha256": daemon_hash,
            "installed_client": client,
            "client_sha256": client_hash,
            "external_name": external or None,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

install -d -m 0755 "$DROPIN_DIR"
DROPIN_TEMP="$DIRECTORY/dropin.new"
cat >"$DROPIN_TEMP" <<EOF
[Service]
ExecStart=
ExecStart=$INSTALLED_BINARY
Environment=RESOLVED_RS_REPLACEMENT_TRANSACTION=$TRANSACTION
EOF
install -m 0644 "$DROPIN_TEMP" "$DROPIN_PATH"

cat >"$DIRECTORY/guard.new" <<EOF
[Unit]
Description=Rollback guard for a pending systemd-resolved-rs replacement
After=systemd-resolved.service network-online.target
Requires=systemd-resolved.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SYSTEM_COPY --guard

[Install]
WantedBy=multi-user.target
EOF
install -m 0644 "$DIRECTORY/guard.new" "$GUARD_UNIT"

: >"$DIRECTORY/pending"
ln -sfn "$DIRECTORY" "$ACTIVE_LINK"

rollback_on_failure() {
    status=$?
    if ((status != 0)); then
        printf 'Replacement transaction failed; restoring the previous resolver.\n' >&2
        restore_transaction "$TRANSACTION" || true
    fi
    exit "$status"
}
trap rollback_on_failure EXIT HUP INT TERM

systemctl daemon-reload
systemctl unmask systemd-resolved.service >/dev/null 2>&1 || true
systemctl enable "$GUARD_NAME" >/dev/null
systemctl restart systemd-resolved.service

healthy=false
for _ in {1..100}; do
    if health_check "$TRANSACTION"; then
        healthy=true
        break
    fi
    sleep 0.1
done
[[ $healthy == true ]]

trap - EXIT HUP INT TERM
printf '%s\n' "$(date --utc --iso-8601=seconds)" >"$DIRECTORY/switched-at"
printf 'Resolver transaction %s is active and pending post-reboot confirmation.\n' "$TRANSACTION"
printf 'After a successful reboot, confirm with:\n'
printf '  sudo %s --confirm %s\n' "$SYSTEM_COPY" "$TRANSACTION"
printf 'Rollback remains available with:\n'
printf '  sudo %s --rollback %s\n' "$SYSTEM_COPY" "$TRANSACTION"
