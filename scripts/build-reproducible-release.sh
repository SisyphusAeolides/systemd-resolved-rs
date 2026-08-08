#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$ROOT/target/reproducible-release"

usage() {
    cat <<'EOF'
Usage: scripts/build-reproducible-release.sh [--output PATH]

Builds the release daemon, client, and NSS module twice in isolated target
directories with deterministic metadata. Both binaries and normalized package
tarballs must be byte-identical.
EOF
}

while (($#)); do
    case "$1" in
        --output)
            OUTPUT=${2:?missing output path}
            shift 2
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

for command in cargo cmp git gzip make python3 sha256sum tar; do
    command -v "$command" >/dev/null || {
        printf 'Required command is missing: %s\n' "$command" >&2
        exit 2
    }
done

OUTPUT="$(readlink -m "$OUTPUT")"
SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct HEAD)"
UPSTREAM_COMMIT="$(cat "$ROOT/compat/upstream-systemd/commit")"
WORK="$(mktemp -d -t resolved-rs-reproducible.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"

export SOURCE_DATE_EPOCH
export TZ=UTC
export LC_ALL=C
export LANG=C
export ZERO_AR_DATE=1
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$ROOT=/usr/src/systemd-resolved-rs -C link-arg=-Wl,--build-id=sha1"
export CFLAGS="${CFLAGS:-} -ffile-prefix-map=$ROOT=/usr/src/systemd-resolved-rs -fdebug-prefix-map=$ROOT=/usr/src/systemd-resolved-rs"
export CXXFLAGS="${CXXFLAGS:-} -ffile-prefix-map=$ROOT=/usr/src/systemd-resolved-rs -fdebug-prefix-map=$ROOT=/usr/src/systemd-resolved-rs"
export FFLAGS="${FFLAGS:-} -ffile-prefix-map=$ROOT=/usr/src/systemd-resolved-rs -fdebug-prefix-map=$ROOT=/usr/src/systemd-resolved-rs"

build_once() {
    local ordinal=$1
    local target="$WORK/target-$ordinal"
    local stage="$WORK/stage-$ordinal"
    local package="$WORK/systemd-resolved-rs-$ordinal.tar.gz"
    CARGO_TARGET_DIR="$target" cargo build \
        --manifest-path "$ROOT/Cargo.toml" \
        --release --all-features --locked

    make -C "$ROOT/nss" clean
    make -C "$ROOT/nss" all

    install -d -m 0755 \
        "$stage/usr/lib/systemd" \
        "$stage/usr/bin" \
        "$stage/usr/lib64" \
        "$stage/usr/lib/systemd/system" \
        "$stage/usr/lib/tmpfiles.d" \
        "$stage/usr/lib/systemd-resolved-rs/scripts"
    install -m 0755 "$target/release/systemd-resolved" \
        "$stage/usr/lib/systemd/systemd-resolved"
    install -m 0755 "$target/release/resolvectl" \
        "$stage/usr/bin/resolvectl"
    install -m 0755 "$ROOT/nss/libnss_resolve.so.2" \
        "$stage/usr/lib64/libnss_resolve.so.2"
    install -m 0644 "$ROOT/packaging/systemd/systemd-resolved.service" \
        "$stage/usr/lib/systemd/system/systemd-resolved.service"
    install -m 0644 "$ROOT/packaging/systemd/systemd-resolved-varlink.socket" \
        "$stage/usr/lib/systemd/system/systemd-resolved-varlink.socket"
    if [[ -f $ROOT/packaging/systemd/systemd-resolved-monitor.socket ]]; then
        install -m 0644 "$ROOT/packaging/systemd/systemd-resolved-monitor.socket" \
            "$stage/usr/lib/systemd/system/systemd-resolved-monitor.socket"
    fi
    install -m 0644 "$ROOT/packaging/tmpfiles/systemd-resolved.conf" \
        "$stage/usr/lib/tmpfiles.d/systemd-resolved.conf"
    for script in install-replace.sh uninstall-restore.sh boot-smoke.sh preflight-replacement.sh; do
        install -m 0755 "$ROOT/scripts/$script" \
            "$stage/usr/lib/systemd-resolved-rs/scripts/$script"
    done

    find "$stage" -exec touch --no-dereference --date="@$SOURCE_DATE_EPOCH" '{}' +
    (
        cd "$stage"
        find . -type f -print0 | sort -z | xargs -0 sha256sum \
            >"$WORK/files-$ordinal.sha256"
        tar \
            --sort=name \
            --format=posix \
            --owner=0 \
            --group=0 \
            --numeric-owner \
            --mtime="@$SOURCE_DATE_EPOCH" \
            --pax-option=delete=atime,delete=ctime \
            -cf - . | gzip -n -9 >"$package"
    )
    cp "$target/release/systemd-resolved" "$WORK/systemd-resolved-$ordinal"
    cp "$target/release/resolvectl" "$WORK/resolvectl-$ordinal"
    cp "$ROOT/nss/libnss_resolve.so.2" "$WORK/libnss_resolve-$ordinal.so.2"
}

build_once 1
build_once 2

cmp "$WORK/systemd-resolved-1" "$WORK/systemd-resolved-2"
cmp "$WORK/resolvectl-1" "$WORK/resolvectl-2"
cmp "$WORK/libnss_resolve-1.so.2" "$WORK/libnss_resolve-2.so.2"
cmp "$WORK/files-1.sha256" "$WORK/files-2.sha256"
cmp "$WORK/systemd-resolved-rs-1.tar.gz" "$WORK/systemd-resolved-rs-2.tar.gz"

cp "$WORK/systemd-resolved-rs-1.tar.gz" "$OUTPUT/systemd-resolved-rs.tar.gz"
cp "$WORK/files-1.sha256" "$OUTPUT/files.sha256"
cp "$WORK/systemd-resolved-1" "$OUTPUT/systemd-resolved"
cp "$WORK/resolvectl-1" "$OUTPUT/resolvectl"
cp "$WORK/libnss_resolve-1.so.2" "$OUTPUT/libnss_resolve.so.2"

python3 - \
    "$OUTPUT/manifest.json" "$SOURCE_COMMIT" "$SOURCE_TREE" "$UPSTREAM_COMMIT" \
    "$SOURCE_DATE_EPOCH" "$OUTPUT/systemd-resolved" "$OUTPUT/resolvectl" \
    "$OUTPUT/libnss_resolve.so.2" "$OUTPUT/systemd-resolved-rs.tar.gz" \
    "$OUTPUT/files.sha256" <<'PY'
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
    source_date_epoch,
    *artifact_paths,
) = sys.argv[1:]

def artifact(value: str) -> dict[str, object]:
    path = Path(value)
    return {
        "name": path.name,
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }

payload = {
    "schema": 1,
    "reproducible": True,
    "source_commit": source_commit,
    "source_tree": source_tree,
    "upstream_commit": upstream_commit,
    "source_date_epoch": int(source_date_epoch),
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "artifacts": [artifact(value) for value in artifact_paths],
}
Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

make -C "$ROOT/nss" clean
printf 'Reproducible release verified at %s.\n' "$OUTPUT"
