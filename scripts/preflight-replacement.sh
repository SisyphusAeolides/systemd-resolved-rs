#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REFERENCE="127.0.0.53:53"
CANDIDATE="127.0.0.1:10553"
CANDIDATE_ALT="127.0.0.1:10554"
BINARY="$ROOT/target/release/systemd-resolved"
CLIENT="$ROOT/target/release/resolvectl"
OUTPUT=""
CASE_FILES=()
EXTRA_ENV=()
BUILD=true
KEEP=false

usage() {
    cat <<'EOF'
Usage: scripts/preflight-replacement.sh [OPTIONS]

Runs systemd-resolved-rs beside the installed resolver on high, private ports.
It does not stop services, replace /etc/resolv.conf, install files, or alter NSS.

Options:
  --reference HOST:PORT   Existing resolver endpoint (default 127.0.0.53:53)
  --candidate HOST:PORT   Candidate endpoint (default 127.0.0.1:10553)
  --candidate-alt HOST:PORT
                          Candidate proxy endpoint (default 127.0.0.1:10554)
  --binary PATH           Candidate daemon binary
  --client PATH           Candidate resolvectl binary
  --case-file PATH        Additional NAME:TYPE differential cases; repeatable
  --environment K=V       Additional candidate environment; repeatable
  --output PATH           Write the rollback/preflight archive here
  --no-build              Do not build missing binaries
  --keep-workdir          Preserve the temporary directory
  -h, --help              Show this help
EOF
}

while (($#)); do
    case "$1" in
        --reference)
            REFERENCE=${2:?missing reference endpoint}
            shift 2
            ;;
        --candidate)
            CANDIDATE=${2:?missing candidate endpoint}
            shift 2
            ;;
        --candidate-alt)
            CANDIDATE_ALT=${2:?missing candidate proxy endpoint}
            shift 2
            ;;
        --binary)
            BINARY=${2:?missing binary path}
            shift 2
            ;;
        --client)
            CLIENT=${2:?missing client path}
            shift 2
            ;;
        --case-file)
            CASE_FILES+=("${2:?missing case-file path}")
            shift 2
            ;;
        --environment)
            EXTRA_ENV+=("${2:?missing environment assignment}")
            shift 2
            ;;
        --output)
            OUTPUT=${2:?missing output path}
            shift 2
            ;;
        --no-build)
            BUILD=false
            shift
            ;;
        --keep-workdir)
            KEEP=true
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

for command in python3 sha256sum stat tar readlink; do
    command -v "$command" >/dev/null || {
        printf 'Required command is missing: %s\n' "$command" >&2
        exit 2
    }
done

for assignment in "${EXTRA_ENV[@]}"; do
    [[ $assignment == *=* && $assignment != =* ]] || {
        printf 'Invalid --environment assignment: %s\n' "$assignment" >&2
        exit 2
    }
done

if [[ $BUILD == true && (! -x $BINARY || ! -x $CLIENT) ]]; then
    cargo build --manifest-path "$ROOT/Cargo.toml" --release --all-features --locked
fi
[[ -x $BINARY ]] || {
    printf 'Candidate daemon is not executable: %s\n' "$BINARY" >&2
    exit 2
}
[[ -x $CLIENT ]] || {
    printf 'Candidate client is not executable: %s\n' "$CLIENT" >&2
    exit 2
}

WORK="$(mktemp -d -t resolved-rs-preflight.XXXXXX)"
RUN_DIR="$WORK/run"
SNAPSHOT="$WORK/snapshot"
mkdir -p "$RUN_DIR" "$SNAPSHOT"
DAEMON_PID=""

cleanup() {
    status=$?
    if [[ -n $DAEMON_PID ]]; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        for _ in {1..100}; do
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 0.05
        done
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            kill -KILL "$DAEMON_PID" 2>/dev/null || true
        fi
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    if ((status != 0)); then
        printf '\nPreflight failed. Candidate log follows:\n' >&2
        cat "$WORK/candidate.log" >&2 2>/dev/null || true
        printf 'Work directory: %s\n' "$WORK" >&2
    fi
    if [[ $KEEP != true && $status -eq 0 ]]; then
        rm -rf "$WORK"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

capture_file() {
    local source=$1
    local name=$2
    if [[ -e $source || -L $source ]]; then
        cp -a --no-dereference "$source" "$SNAPSHOT/$name"
        stat --printf='%n\nmode=%a\nuid=%u\ngid=%g\nsize=%s\ninode=%i\n' \
            "$source" >"$SNAPSHOT/$name.stat" 2>&1 || true
        readlink "$source" >"$SNAPSHOT/$name.readlink" 2>/dev/null || :
        sha256sum "$source" >"$SNAPSHOT/$name.sha256" 2>/dev/null || :
    else
        printf 'missing\n' >"$SNAPSHOT/$name.missing"
    fi
}

capture_command() {
    local name=$1
    shift
    "$@" >"$SNAPSHOT/$name.stdout" 2>"$SNAPSHOT/$name.stderr" || \
        printf '%s\n' "$?" >"$SNAPSHOT/$name.status"
}

capture_file /etc/resolv.conf resolv.conf
capture_file /etc/nsswitch.conf nsswitch.conf
capture_file /etc/systemd/resolved.conf resolved.conf
if [[ -d /etc/systemd/resolved.conf.d ]]; then
    cp -a /etc/systemd/resolved.conf.d "$SNAPSHOT/resolved.conf.d"
fi

if command -v systemctl >/dev/null; then
    capture_command systemd-resolved-unit systemctl cat systemd-resolved.service
    capture_command systemd-resolved-show systemctl show systemd-resolved.service
    capture_command systemd-resolved-status systemctl status --no-pager systemd-resolved.service
    capture_command systemd-resolved-sockets systemctl list-sockets --no-pager '*resolve*'
fi
if command -v resolvectl >/dev/null; then
    capture_command reference-resolvectl-status resolvectl status
    capture_command reference-resolvectl-statistics resolvectl statistics
fi
if command -v busctl >/dev/null; then
    capture_command reference-dbus-manager busctl --system --no-pager --xml-interface \
        introspect org.freedesktop.resolve1 /org/freedesktop/resolve1 \
        org.freedesktop.resolve1.Manager
fi
if command -v networkctl >/dev/null; then
    capture_command networkctl-status networkctl status --all --no-pager
fi

REFERENCE_FINGERPRINT="$WORK/reference-resolv-conf.fingerprint"
{
    readlink /etc/resolv.conf 2>/dev/null || :
    stat --printf='%a:%u:%g:%s:%i\n' /etc/resolv.conf 2>/dev/null || :
    sha256sum /etc/resolv.conf 2>/dev/null || :
} >"$REFERENCE_FINGERPRINT"

printf 'Starting candidate on %s (proxy %s)\n' "$CANDIDATE" "$CANDIDATE_ALT"
env \
    "RESOLVED_RS_STUB_ADDR=$CANDIDATE" \
    "RESOLVED_RS_STUB_ADDR_ALT=$CANDIDATE_ALT" \
    "RESOLVED_RS_RUN_DIR=$RUN_DIR" \
    "${EXTRA_ENV[@]}" \
    "$BINARY" >"$WORK/candidate.log" 2>&1 &
DAEMON_PID=$!

ready=false
for _ in {1..200}; do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        break
    fi
    if python3 - "$CANDIDATE" <<'PY' >/dev/null 2>&1
import socket
import struct
import sys

value = sys.argv[1]
if value.startswith('['):
    closing = value.index(']')
    host = value[1:closing]
    port = int(value[closing + 2:])
else:
    host, port_text = value.rsplit(':', 1)
    port = int(port_text)
family = socket.AF_INET6 if ':' in host else socket.AF_INET
packet = bytearray(struct.pack('!HHHHHH', 0x5151, 0x0100, 1, 0, 0, 0))
packet.extend(b'\x09localhost\0\0\1\0\1')
with socket.socket(family, socket.SOCK_DGRAM) as stream:
    stream.settimeout(0.2)
    stream.sendto(packet, (host, port))
    response, _ = stream.recvfrom(4096)
    if len(response) < 12 or response[:2] != b'QQ':
        raise SystemExit(1)
PY
    then
        ready=true
        break
    fi
    sleep 0.05
done

if [[ $ready != true ]]; then
    printf 'Candidate did not become ready\n' >&2
    exit 1
fi

DIFF_ARGS=(
    --reference "$REFERENCE"
    --candidate "$CANDIDATE"
    --protocol both
    --repeat 3
    --jobs 8
    --json "$WORK/differential.json"
)
for case_file in "${CASE_FILES[@]}"; do
    DIFF_ARGS+=(--case-file "$case_file")
done
python3 "$ROOT/tests/differential-resolved.py" "${DIFF_ARGS[@]}" | tee "$WORK/differential.log"

"$CLIENT" --socket "$RUN_DIR/io.systemd.Resolve" status \
    >"$WORK/candidate-resolvectl-status.txt"
"$CLIENT" --socket "$RUN_DIR/io.systemd.Resolve" statistics \
    >"$WORK/candidate-resolvectl-statistics.txt"
"$CLIENT" --socket "$RUN_DIR/io.systemd.Resolve" query localhost \
    >"$WORK/candidate-resolvectl-query.txt"

AFTER_FINGERPRINT="$WORK/after-resolv-conf.fingerprint"
{
    readlink /etc/resolv.conf 2>/dev/null || :
    stat --printf='%a:%u:%g:%s:%i\n' /etc/resolv.conf 2>/dev/null || :
    sha256sum /etc/resolv.conf 2>/dev/null || :
} >"$AFTER_FINGERPRINT"
cmp --silent "$REFERENCE_FINGERPRINT" "$AFTER_FINGERPRINT" || {
    printf '/etc/resolv.conf changed during non-destructive preflight\n' >&2
    exit 1
}

cp "$WORK/candidate.log" "$SNAPSHOT/"
cp "$WORK/differential.json" "$SNAPSHOT/"
cp "$WORK/differential.log" "$SNAPSHOT/"
cp "$WORK/candidate-resolvectl-"*.txt "$SNAPSHOT/"
printf '%s\n' "$REFERENCE" >"$SNAPSHOT/reference-endpoint"
printf '%s\n' "$CANDIDATE" >"$SNAPSHOT/candidate-endpoint"
printf '%s\n' "$(date --utc --iso-8601=seconds)" >"$SNAPSHOT/captured-at"

if [[ -z $OUTPUT ]]; then
    OUTPUT="$PWD/systemd-resolved-rs-preflight-$(date --utc +%Y%m%dT%H%M%SZ).tar.gz"
fi
OUTPUT="$(realpath -m "$OUTPUT")"
tar --create --gzip --file="$OUTPUT" -C "$WORK" snapshot
printf '\nNon-destructive replacement preflight passed.\n'
printf 'Rollback and differential snapshot: %s\n' "$OUTPUT"
printf 'The installed resolver remained active and /etc/resolv.conf was unchanged.\n'
