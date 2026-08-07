#!/usr/bin/env bash
set -euo pipefail

STATE_ROOT=/var/lib/systemd-resolved-rs
SYSTEM_COPY=/usr/lib/systemd/systemd-resolved-rs-switch
GUARD_UNIT=/etc/systemd/system/systemd-resolved-rs-guard.service
DROPIN_DIR=/etc/systemd/system/systemd-resolved.service.d
DROPIN_PATH=$DROPIN_DIR/90-systemd-resolved-rs.conf
ACTIVE_LINK=$STATE_ROOT/active
MODE=install
CERTIFICATE=
TRANSACTION=
EXTERNAL_NAME=

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/switch-resolved-transactionally.sh --certificate FILE [OPTIONS]
  sudo scripts/switch-resolved-transactionally.sh --confirm TRANSACTION
  sudo scripts/switch-resolved-transactionally.sh --rollback [TRANSACTION]
  sudo /usr/lib/systemd/systemd-resolved-rs-switch --guard

The install mode requires a certificate whose every gate passed and whose binary
hash matches. It keeps the distro package installed and overrides only the
systemd service command. Any failed health check restores the exact prior
service override and restarts the original resolver.

Options:
  --certificate FILE      Certified report from certify-replacement.sh
  --external-name NAME    Optional external DNS name for post-switch validation
  --confirm TRANSACTION   Confirm a healthy transaction after reboot
  --rollback [TRANSACTION]
                          Restore the selected or active transaction
  --guard                 Internal boot-guard mode
  -h, --help              Show this help
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

for command in busctl flock getent install python3 readlink sha256sum systemctl; do
    command -v "$command" >/dev/null || {
        printf 'Required command is missing: %s\n' "$command" >&2
        exit 2
    }
done

install -d -m 0700 "$STATE_ROOT"
exec 9>"$STATE_ROOT/transaction.lock"
flock -x 9

active_transaction() {
    if [[ -L $ACTIVE_LINK ]]; then
        basename "$(readlink -f "$ACTIVE_LINK")"
    fi
}

health_check() {
    local transaction=$1
    local directory="$STATE_ROOT/transactions/$transaction"
    local metadata="$directory/transaction.json"
    [[ -s $metadata ]] || return 1

    local binary client expected_pid_path external
    readarray -t values < <(python3 - "$metadata" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data["installed_binary"])
print(data["installed_client"])
print(data.get("external_name") or "")
PY
    )
    binary=${values[0]}
    client=${values[1]}
    external=${values[2]}

    systemctl is-active --quiet systemd-resolved.service || return 1
    local pid
    pid=$(systemctl show --property MainPID --value systemd-resolved.service)
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    expected_pid_path=$(readlink -f "/proc/$pid/exe") || return 1
    [[ $expected_pid_path == "$(readlink -f "$binary")" ]] || return 1

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
    header = stream.recv(2)
    if len(header) != 2:
        raise SystemExit(1)
    length = struct.unpack("!H", header)[0]
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
    [[ -d $directory ]] || {
        printf 'Unknown transaction: %s\n' "$transaction" >&2
        return 1
    }

    if [[ -e $directory/dropin.existed ]]; then
        install -d -m 0755 "$DROPIN_DIR"
        rm -f "$DROPIN_PATH"
        cp -a --no-dereference "$directory/dropin.previous" "$DROPIN_PATH"
    else
        rm -f "$DROPIN_PATH"
        rmdir "$DROPIN_DIR" 2>/dev/null || true
    fi

    systemctl daemon-reload
    systemctl unmask systemd-resolved.service >/dev/null 2>&1 || true
    systemctl restart systemd-resolved.service

    rm -f "$directory/pending"
    printf '%s\n' "$(date --utc --iso-8601=seconds)" >"$directory/rolled-back-at"
    if [[ -L $ACTIVE_LINK ]] && [[ $(active_transaction) == "$transaction" ]]; then
        rm -f "$ACTIVE_LINK"
    fi
    printf 'Rolled back resolver transaction %s.\n' "$transaction"
}

case "$MODE" in
    guard)
        transaction=$(active_transaction || true)
        [[ -n $transaction ]] || exit 0
        directory="$STATE_ROOT/transactions/$transaction"
        [[ -e $directory/pending ]] || exit 0
        if health_check "$transaction"; then
            printf 'Resolver transaction %s passed the boot guard.\n' "$transaction"
            exit 0
        fi
        printf 'Resolver transaction %s failed the boot guard; rolling back.\n' "$transaction" >&2
        restore_transaction "$transaction"
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

readarray -t certificate_values < <(python3 - "$CERTIFICATE" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("certified") is not True:
    raise SystemExit("certificate is not certified")
failed = [gate for gate in data.get("gates", []) if gate.get("status") != "pass"]
if failed:
    raise SystemExit("certificate contains a nonpassing gate")
print(data["source_commit"])
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

SOURCE_COMMIT=${certificate_values[0]}
BINARY=${certificate_values[1]}
BINARY_SHA256=${certificate_values[2]}
CLIENT=${certificate_values[3]}
CLIENT_SHA256=${certificate_values[4]}
UPSTREAM_COMMIT=${certificate_values[5]}

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

TRANSACTION="$(date --utc +%Y%m%dT%H%M%SZ)-${SOURCE_COMMIT:0:12}"
DIRECTORY="$STATE_ROOT/transactions/$TRANSACTION"
INSTALL_ROOT="/usr/lib/systemd/systemd-resolved-rs/$SOURCE_COMMIT"
INSTALLED_BINARY="$INSTALL_ROOT/systemd-resolved"
INSTALLED_CLIENT="$INSTALL_ROOT/resolvectl"
install -d -m 0700 "$DIRECTORY"
install -d -m 0755 "$INSTALL_ROOT"
install -m 0755 "$BINARY" "$INSTALLED_BINARY"
install -m 0755 "$CLIENT" "$INSTALLED_CLIENT"
install -m 0755 "$0" "$SYSTEM_COPY"

if [[ -e $DROPIN_PATH || -L $DROPIN_PATH ]]; then
    cp -a --no-dereference "$DROPIN_PATH" "$DIRECTORY/dropin.previous"
    : >"$DIRECTORY/dropin.existed"
fi
systemctl cat systemd-resolved.service >"$DIRECTORY/unit-before.txt" 2>&1 || true
systemctl show systemd-resolved.service >"$DIRECTORY/unit-properties-before.txt" 2>&1 || true
cp -a --no-dereference /etc/resolv.conf "$DIRECTORY/resolv.conf.before" 2>/dev/null || true
cp -a --no-dereference /etc/nsswitch.conf "$DIRECTORY/nsswitch.conf.before" 2>/dev/null || true

python3 - \
    "$DIRECTORY/transaction.json" "$TRANSACTION" "$SOURCE_COMMIT" "$UPSTREAM_COMMIT" \
    "$CERTIFICATE" "$INSTALLED_BINARY" "$INSTALLED_CLIENT" "$EXTERNAL_NAME" <<'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

(
    path,
    transaction,
    source,
    upstream,
    certificate,
    binary,
    client,
    external,
) = sys.argv[1:]
Path(path).write_text(
    json.dumps(
        {
            "schema": 1,
            "transaction": transaction,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_commit": source,
            "upstream_commit": upstream,
            "certificate": certificate,
            "installed_binary": binary,
            "installed_client": client,
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
cat >"$DROPIN_PATH" <<EOF
[Service]
ExecStart=
ExecStart=$INSTALLED_BINARY
Environment=RESOLVED_RS_REPLACEMENT_TRANSACTION=$TRANSACTION
EOF
chmod 0644 "$DROPIN_PATH"

cat >"$GUARD_UNIT" <<EOF
[Unit]
Description=Rollback guard for a pending systemd-resolved-rs replacement
After=systemd-resolved.service
Requires=systemd-resolved.service

[Service]
Type=oneshot
ExecStart=$SYSTEM_COPY --guard

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$GUARD_UNIT"

: >"$DIRECTORY/pending"
ln -sfn "$DIRECTORY" "$ACTIVE_LINK"

rollback_on_failure() {
    status=$?
    if ((status != 0)); then
        printf 'Replacement transaction failed; restoring the original resolver.\n' >&2
        restore_transaction "$TRANSACTION" || true
    fi
    exit "$status"
}
trap rollback_on_failure EXIT HUP INT TERM

systemctl daemon-reload
systemctl enable systemd-resolved-rs-guard.service >/dev/null
systemctl unmask systemd-resolved.service >/dev/null 2>&1 || true
systemctl restart systemd-resolved.service

for _ in {1..100}; do
    health_check "$TRANSACTION" && break
    sleep 0.1
done
health_check "$TRANSACTION"

trap - EXIT HUP INT TERM
printf '%s\n' "$(date --utc --iso-8601=seconds)" >"$DIRECTORY/switched-at"
printf 'Resolver transaction %s is active and pending post-reboot confirmation.\n' "$TRANSACTION"
printf 'After a successful reboot, confirm with:\n'
printf '  sudo %s --confirm %s\n' "$SYSTEM_COPY" "$TRANSACTION"
printf 'Manual rollback remains available with:\n'
printf '  sudo %s --rollback %s\n' "$SYSTEM_COPY" "$TRANSACTION"
