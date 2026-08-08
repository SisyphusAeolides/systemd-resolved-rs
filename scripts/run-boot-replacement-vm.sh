#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$ROOT/target/release/systemd-resolved"
CLIENT="$ROOT/target/release/resolvectl"
OUTPUT="$ROOT/target/boot-replacement-vm"
KEEP=false

usage() {
    cat <<'EOF'
Usage: scripts/run-boot-replacement-vm.sh [OPTIONS]

Builds a disposable Ubuntu disk with mkosi, boots it under QEMU twice, verifies
the candidate resolver on both boots, then removes the service override and
verifies the distro resolver before shutdown.

Options:
  --binary PATH   Candidate daemon
  --client PATH   Candidate resolvectl
  --output PATH   Stable evidence directory
  --keep          Preserve the mkosi working directory
  -h, --help      Show this help
EOF
}

while (($#)); do
    case "$1" in
        --binary)
            BINARY=${2:?missing binary path}
            shift 2
            ;;
        --client)
            CLIENT=${2:?missing client path}
            shift 2
            ;;
        --output)
            OUTPUT=${2:?missing output path}
            shift 2
            ;;
        --keep)
            KEEP=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$1" >&2
            exit 2
            ;;
    esac
done

for command in git mkosi python3 qemu-system-x86_64 sha256sum sudo timeout; do
    command -v "$command" >/dev/null || {
        printf 'Required command is missing: %s\n' "$command" >&2
        exit 2
    }
done
[[ -x $BINARY && -x $CLIENT ]] || {
    printf 'Candidate binaries are missing.\n' >&2
    exit 2
}

BINARY="$(readlink -f "$BINARY")"
CLIENT="$(readlink -f "$CLIENT")"
OUTPUT="$(readlink -m "$OUTPUT")"
SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
UPSTREAM_COMMIT="$(cat "$ROOT/compat/upstream-systemd/commit")"
DAEMON_HASH="$(sha256sum "$BINARY" | awk '{print $1}')"
CLIENT_HASH="$(sha256sum "$CLIENT" | awk '{print $1}')"
PASS_MARKER="RESOLVED_RS_BOOT_PROOF_PASS_${SOURCE_TREE}_${DAEMON_HASH}"
ROLLBACK_MARKER="RESOLVED_RS_BOOT_ROLLBACK_PASS_${UPSTREAM_COMMIT}"

rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"
WORK="$(mktemp -d -t resolved-rs-boot-vm.XXXXXX)"
cleanup() {
    status=$?
    if [[ $KEEP == true ]]; then
        printf 'Boot-proof work tree retained at %s\n' "$WORK" >&2
    else
        rm -rf "$WORK"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

EXTRA="$WORK/mkosi.extra"
install -d -m 0755 \
    "$EXTRA/usr/lib/systemd" \
    "$EXTRA/usr/local/bin" \
    "$EXTRA/etc/systemd/system/systemd-resolved.service.d" \
    "$EXTRA/etc/systemd/system/multi-user.target.wants" \
    "$EXTRA/var/lib/resolved-rs-proof"
install -m 0755 "$BINARY" "$EXTRA/usr/lib/systemd/systemd-resolved-rs"
install -m 0755 "$CLIENT" "$EXTRA/usr/local/bin/resolvectl-rs"

cat >"$EXTRA/etc/systemd/system/systemd-resolved.service.d/99-resolved-rs.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-resolved-rs
Environment=RESOLVED_RS_MDNS=no
Environment=RESOLVED_RS_MDNS_RESPONDER=no
EOF

cat >"$EXTRA/usr/local/bin/resolved-rs-boot-proof" <<EOF
#!/bin/bash
set -euo pipefail

COUNT_FILE=/var/lib/resolved-rs-proof/boot-count
count=0
if [[ -s \$COUNT_FILE ]]; then
    count=\$(cat \$COUNT_FILE)
fi
count=\$((count + 1))
printf '%s\\n' "\$count" >\$COUNT_FILE
sync

wait_candidate() {
    for _ in {1..150}; do
        if systemctl is-active --quiet systemd-resolved.service; then
            pid=\$(systemctl show --property MainPID --value systemd-resolved.service)
            if [[ \$pid =~ ^[1-9][0-9]*$ ]] && \
               [[ \$(readlink -f /proc/\$pid/exe) == /usr/lib/systemd/systemd-resolved-rs ]]; then
                return 0
            fi
        fi
        sleep 0.1
    done
    return 1
}

check_dns() {
    python3 - <<'PY'
import socket
import struct

query = (
    struct.pack("!HHHHHH", 0x4254, 0x0100, 1, 0, 0, 0)
    + b"\\x09localhost\\0"
    + struct.pack("!HH", 1, 1)
)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
    stream.settimeout(3)
    stream.sendto(query, ("127.0.0.53", 53))
    response, _ = stream.recvfrom(65535)
    if len(response) < 12 or response[:2] != b"BT" or response[3] & 0x0F:
        raise SystemExit(1)
with socket.create_connection(("127.0.0.53", 53), timeout=3) as stream:
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
    if response[:2] != b"BT" or response[3] & 0x0F:
        raise SystemExit(1)
PY
}

check_candidate() {
    wait_candidate
    check_dns
    busctl --system --no-pager introspect \
        org.freedesktop.resolve1 /org/freedesktop/resolve1 \
        org.freedesktop.resolve1.Manager >/dev/null
    /usr/local/bin/resolvectl-rs status >/dev/null
    /usr/local/bin/resolvectl-rs statistics >/dev/null
    /usr/local/bin/resolvectl-rs query localhost >/dev/null
}

check_candidate
printf 'RESOLVED_RS_CANDIDATE_BOOT_%s_%s\\n' "\$count" '$DAEMON_HASH' >/dev/console

if [[ \$count -eq 1 ]]; then
    systemctl reboot
    exit 0
fi
if [[ \$count -ne 2 ]]; then
    printf 'unexpected boot count %s\\n' "\$count" >/dev/console
    systemctl poweroff
    exit 1
fi

rm -f /etc/systemd/system/systemd-resolved.service.d/99-resolved-rs.conf
rmdir /etc/systemd/system/systemd-resolved.service.d 2>/dev/null || true
systemctl daemon-reload
systemctl restart systemd-resolved.service
for _ in {1..150}; do
    if systemctl is-active --quiet systemd-resolved.service; then
        pid=\$(systemctl show --property MainPID --value systemd-resolved.service)
        if [[ \$pid =~ ^[1-9][0-9]*$ ]] && \
           [[ \$(readlink -f /proc/\$pid/exe) != /usr/lib/systemd/systemd-resolved-rs ]]; then
            break
        fi
    fi
    sleep 0.1
done
pid=\$(systemctl show --property MainPID --value systemd-resolved.service)
[[ \$pid =~ ^[1-9][0-9]*$ ]]
[[ \$(readlink -f /proc/\$pid/exe) != /usr/lib/systemd/systemd-resolved-rs ]]
check_dns
busctl --system --no-pager introspect \
    org.freedesktop.resolve1 /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager >/dev/null
printf '%s\\n' '$ROLLBACK_MARKER' >/dev/console
printf '%s\\n' '$PASS_MARKER' >/dev/console
sync
systemctl poweroff
EOF
chmod 0755 "$EXTRA/usr/local/bin/resolved-rs-boot-proof"

cat >"$EXTRA/etc/systemd/system/resolved-rs-boot-proof.service" <<'EOF'
[Unit]
Description=Two-boot systemd-resolved-rs replacement proof
After=systemd-resolved.service dbus.service network.target
Requires=systemd-resolved.service dbus.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/resolved-rs-boot-proof
TimeoutStartSec=5min

[Install]
WantedBy=multi-user.target
EOF
ln -s ../resolved-rs-boot-proof.service \
    "$EXTRA/etc/systemd/system/multi-user.target.wants/resolved-rs-boot-proof.service"

cat >"$WORK/mkosi.conf" <<'EOF'
[Distribution]
Distribution=ubuntu
Release=noble

[Output]
Format=disk
ImageId=resolved-rs-boot-proof
Output=resolved-rs-boot-proof.raw
CompressOutput=no

[Content]
Bootable=yes
Packages=systemd,systemd-resolved,dbus,python3,iproute2,ca-certificates,libssl3,libgfortran5,libgcc-s1,libstdc++6
ExtraTrees=mkosi.extra

[Validation]
SecureBoot=no
EOF

sudo mkosi --directory "$WORK" --force build \
    >"$OUTPUT/mkosi-build.log" 2>&1
IMAGE="$WORK/resolved-rs-boot-proof.raw"
[[ -s $IMAGE ]] || {
    printf 'mkosi did not produce %s\n' "$IMAGE" >&2
    exit 1
}

OVMF=$(find /usr/share/OVMF /usr/share/edk2 -type f \
    \( -name 'OVMF_CODE.fd' -o -name 'OVMF_CODE_4M.fd' -o -name 'OVMF_CODE*.fd' \) \
    2>/dev/null | head -n1)
[[ -n $OVMF ]] || {
    printf 'No OVMF firmware was found.\n' >&2
    exit 1
}

ACCEL=tcg
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    ACCEL=kvm:tcg
fi
set +e
timeout --signal=TERM --kill-after=30s 30m \
    qemu-system-x86_64 \
    -machine "q35,accel=$ACCEL" \
    -cpu max \
    -smp 2 \
    -m 2048 \
    -nographic \
    -no-shutdown \
    -bios "$OVMF" \
    -device virtio-rng-pci \
    -nic user,model=virtio-net-pci \
    -drive "if=virtio,format=raw,file=$IMAGE" \
    >"$OUTPUT/qemu-console.log" 2>&1
QEMU_STATUS=$?
set -e
if ((QEMU_STATUS != 0)); then
    printf 'QEMU boot proof failed with status %s.\n' "$QEMU_STATUS" >&2
    exit "$QEMU_STATUS"
fi

grep -Fq "RESOLVED_RS_CANDIDATE_BOOT_1_$DAEMON_HASH" "$OUTPUT/qemu-console.log"
grep -Fq "RESOLVED_RS_CANDIDATE_BOOT_2_$DAEMON_HASH" "$OUTPUT/qemu-console.log"
grep -Fq "$ROLLBACK_MARKER" "$OUTPUT/qemu-console.log"
grep -Fq "$PASS_MARKER" "$OUTPUT/qemu-console.log"

python3 - \
    "$OUTPUT/evidence.json" "$SOURCE_COMMIT" "$SOURCE_TREE" "$UPSTREAM_COMMIT" \
    "$DAEMON_HASH" "$CLIENT_HASH" "$OUTPUT/mkosi-build.log" \
    "$OUTPUT/qemu-console.log" <<'PY'
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

(
    output,
    source_commit,
    source_tree,
    upstream_commit,
    daemon_hash,
    client_hash,
    build_log,
    console_log,
) = sys.argv[1:]

def artifact(path: str) -> dict[str, object]:
    value = Path(path)
    return {
        "name": value.name,
        "size": value.stat().st_size,
        "sha256": hashlib.sha256(value.read_bytes()).hexdigest(),
    }

payload = {
    "schema": 1,
    "environment": "qemu",
    "distribution": "ubuntu",
    "release": "noble",
    "boot_count": 2,
    "candidate_healthy_each_boot": True,
    "rollback_verified": True,
    "source_commit": source_commit,
    "source_tree": source_tree,
    "upstream_commit": upstream_commit,
    "daemon_sha256": daemon_hash,
    "client_sha256": client_hash,
    "completed_at": datetime.now(timezone.utc).isoformat(),
    "artifacts": [artifact(build_log), artifact(console_log)],
}
Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf 'Two-boot candidate and rollback proof passed under QEMU.\n'
