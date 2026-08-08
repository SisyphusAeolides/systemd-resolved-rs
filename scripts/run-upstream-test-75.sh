#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$ROOT/target/release/systemd-resolved"
CLIENT="$ROOT/target/release/resolvectl"
OUTPUT="$ROOT/target/upstream-test-75"
SYSTEMD_TREE=
KEEP=false

usage() {
    cat <<'EOF'
Usage: sudo-preserving-env scripts/run-upstream-test-75.sh [OPTIONS]

Runs the pinned upstream TEST-75-RESOLVED without changing any recorded upstream
test file. Candidate binaries enter the image through additional mkosi/testdata
overlays and a service drop-in. A proof marker must appear in the captured log.

Options:
  --binary PATH        Candidate systemd-resolved binary
  --client PATH        Candidate resolvectl binary
  --output PATH        Stable output directory
  --systemd-tree PATH  Reuse an exact pinned upstream checkout
  --keep               Keep the temporary upstream checkout
  -h, --help           Show this help
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
        --systemd-tree)
            SYSTEMD_TREE=${2:?missing systemd tree path}
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

for command in git meson ninja python3 sha256sum sudo; do
    command -v "$command" >/dev/null || {
        printf 'Required command is missing: %s\n' "$command" >&2
        exit 2
    }
done
[[ -x $BINARY && -x $CLIENT ]] || {
    printf 'Candidate release binaries are missing.\n' >&2
    exit 2
}

BINARY="$(readlink -f "$BINARY")"
CLIENT="$(readlink -f "$CLIENT")"
OUTPUT="$(readlink -m "$OUTPUT")"
BASELINE="$ROOT/compat/upstream-systemd"
COMMIT="$(cat "$BASELINE/commit")"
RELEASE="$(cat "$BASELINE/release")"
SOURCE_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
DAEMON_HASH="$(sha256sum "$BINARY" | awk '{print $1}')"
CLIENT_HASH="$(sha256sum "$CLIENT" | awk '{print $1}')"
MARKER="RESOLVED_RS_TEST_75_${SOURCE_TREE}_${DAEMON_HASH}"

rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"
LOG="$OUTPUT/TEST-75-RESOLVED.log"

CREATED_TREE=false
if [[ -z $SYSTEMD_TREE ]]; then
    SYSTEMD_TREE="$(mktemp -d -t systemd-test-75.XXXXXX)"
    CREATED_TREE=true
    git clone --filter=blob:none --no-checkout \
        https://github.com/systemd/systemd.git "$SYSTEMD_TREE"
    git -C "$SYSTEMD_TREE" fetch --depth 1 origin "$COMMIT"
    git -C "$SYSTEMD_TREE" checkout --detach "$COMMIT"
else
    SYSTEMD_TREE="$(readlink -f "$SYSTEMD_TREE")"
fi

cleanup() {
    status=$?
    if [[ $CREATED_TREE == true && $KEEP != true ]]; then
        rm -rf "$SYSTEMD_TREE"
    else
        printf 'Upstream tree retained at %s\n' "$SYSTEMD_TREE" >&2
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

[[ $(git -C "$SYSTEMD_TREE" rev-parse HEAD) == "$COMMIT" ]] || {
    printf 'Upstream tree is not at the pinned commit.\n' >&2
    exit 1
}
(
    cd "$SYSTEMD_TREE"
    sha256sum --check --strict "$BASELINE/resolve-source.sha256"
    sha256sum --check --strict "$BASELINE/resolve-tests.sha256"
)

TEST_DIR="$SYSTEMD_TREE/test/TEST-75-RESOLVED"
[[ -d $TEST_DIR ]] || {
    printf 'Pinned systemd tree has no TEST-75-RESOLVED.\n' >&2
    exit 1
}

install_overlay() {
    local root=$1
    install -d -m 0755 \
        "$root/usr/lib/systemd" \
        "$root/usr/bin" \
        "$root/etc/systemd/system/systemd-resolved.service.d"
    install -m 0755 "$BINARY" "$root/usr/lib/systemd/systemd-resolved-rs"
    install -m 0755 "$CLIENT" "$root/usr/bin/resolvectl"
    cat >"$root/usr/lib/systemd/systemd-resolved-rs-wrapper" <<EOF
#!/bin/sh
printf '%s\\n' '$MARKER' >&2
exec /usr/lib/systemd/systemd-resolved-rs "\$@"
EOF
    chmod 0755 "$root/usr/lib/systemd/systemd-resolved-rs-wrapper"
    cat >"$root/etc/systemd/system/systemd-resolved.service.d/99-resolved-rs.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-resolved-rs-wrapper
Environment=RESOLVED_RS_MDNS=yes
EOF
}

install_overlay "$TEST_DIR/mkosi.extra"
install_overlay "$TEST_DIR/testdata"

if [[ -d $TEST_DIR/mkosi.conf.d ]]; then
    cat >"$TEST_DIR/mkosi.conf.d/99-resolved-rs-runtime.conf" <<'EOF'
[Distribution]
Distribution=ubuntu
Release=noble

[Content]
Packages=libssl3,libgfortran5,libgcc-s1,libstdc++6
EOF
fi

MESON_ARGUMENTS=(
    "$SYSTEMD_TREE/build"
    --buildtype=debugoptimized
    -Dtests=true
)
if grep -Eq "option\(['\"]integration-tests['\"]" "$SYSTEMD_TREE/meson_options.txt"; then
    MESON_ARGUMENTS+=( -Dintegration-tests=true )
fi
if grep -Eq "option\(['\"]slow-tests['\"]" "$SYSTEMD_TREE/meson_options.txt"; then
    MESON_ARGUMENTS+=( -Dslow-tests=true )
fi
if [[ ! -f $SYSTEMD_TREE/build/build.ninja ]]; then
    meson setup "${MESON_ARGUMENTS[@]}"
else
    meson setup --reconfigure "${MESON_ARGUMENTS[@]}"
fi
ninja -C "$SYSTEMD_TREE/build"

set +e
{
    printf 'Pinned release: %s\nPinned commit: %s\nSource tree: %s\n' \
        "$RELEASE" "$COMMIT" "$SOURCE_TREE"
    printf 'Candidate daemon SHA-256: %s\n' "$DAEMON_HASH"
    printf 'Candidate client SHA-256: %s\n' "$CLIENT_HASH"
    if [[ -x $TEST_DIR/test.sh ]]; then
        printf 'Using official per-test entrypoint: %s\n' "$TEST_DIR/test.sh"
        sudo --preserve-env=PATH,HOME,TERM \
            env \
            BUILD_DIR="$SYSTEMD_TREE/build" \
            SYSTEMD_INTEGRATION_TESTS=1 \
            TEST_NO_NSPAWN=1 \
            TEST_NO_QEMU=0 \
            "$TEST_DIR/test.sh"
    elif [[ -x $SYSTEMD_TREE/test/run-integration-tests.sh ]]; then
        printf 'Using official integration-test runner.\n'
        sudo --preserve-env=PATH,HOME,TERM \
            env \
            BUILD_DIR="$SYSTEMD_TREE/build" \
            SYSTEMD_INTEGRATION_TESTS=1 \
            TESTS=TEST-75-RESOLVED \
            "$SYSTEMD_TREE/test/run-integration-tests.sh" TEST-75-RESOLVED
    else
        printf 'Using the Meson integration-test entrypoint.\n'
        sudo --preserve-env=PATH,HOME,TERM \
            env SYSTEMD_INTEGRATION_TESTS=1 \
            meson test -C "$SYSTEMD_TREE/build" \
            --no-rebuild --print-errorlogs TEST-75-RESOLVED
    fi
} >"$LOG" 2>&1
STATUS=$?
set -e

(
    cd "$SYSTEMD_TREE"
    sha256sum --check --strict "$BASELINE/resolve-source.sha256"
    sha256sum --check --strict "$BASELINE/resolve-tests.sha256"
) >>"$LOG" 2>&1

if ((STATUS != 0)); then
    printf 'TEST-75-RESOLVED failed; see %s\n' "$LOG" >&2
    exit "$STATUS"
fi
if ! grep -Fq "$MARKER" "$LOG"; then
    printf 'The suite passed without proof that the candidate daemon executed.\n' >&2
    exit 1
fi

python3 - \
    "$OUTPUT/evidence.json" "$RELEASE" "$COMMIT" "$SOURCE_TREE" \
    "$DAEMON_HASH" "$CLIENT_HASH" "$MARKER" "$LOG" <<'PY'
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

(
    output,
    release,
    upstream_commit,
    source_tree,
    daemon_hash,
    client_hash,
    marker,
    log_path,
) = sys.argv[1:]
log = Path(log_path)
payload = {
    "schema": 1,
    "suite": "TEST-75-RESOLVED",
    "unmodified_recorded_upstream_files": True,
    "upstream_release": release,
    "upstream_commit": upstream_commit,
    "source_tree": source_tree,
    "daemon_sha256": daemon_hash,
    "client_sha256": client_hash,
    "runtime_marker": marker,
    "completed_at": datetime.now(timezone.utc).isoformat(),
    "log": {
        "name": log.name,
        "size": log.stat().st_size,
        "sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
    },
}
Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf 'Pinned upstream TEST-75-RESOLVED passed with the candidate daemon.\n'
