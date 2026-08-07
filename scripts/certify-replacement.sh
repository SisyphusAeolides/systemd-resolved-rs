#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$ROOT/target/replacement-certification.json"
BINARY="$ROOT/target/release/systemd-resolved"
CLIENT="$ROOT/target/release/resolvectl"
REFERENCE="127.0.0.53:53"
CANDIDATE="127.0.0.1:10553"
RUN_HOST_TESTS=true
RUN_NETWORK_NAMESPACE_TESTS=true

usage() {
    cat <<'EOF'
Usage: scripts/certify-replacement.sh [OPTIONS]

Produces a JSON certificate only after every locally available release gate passes.
A certificate is deliberately marked uncertified when pinned upstream-suite or
security proof files are missing or do not match the current source and baseline.

Options:
  --output PATH             Certificate destination
  --binary PATH             Release daemon binary
  --client PATH             Release resolvectl binary
  --reference HOST:PORT     Existing resolver used for shadow comparison
  --candidate HOST:PORT     High-port candidate endpoint for shadow comparison
  --no-host-tests           Skip host differential testing (never certifies)
  --no-netns-tests          Skip namespace mDNS/DNS-SD tests (never certifies)
  -h, --help                Show this help
EOF
}

while (($#)); do
    case "$1" in
        --output)
            OUTPUT=${2:?missing output path}
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
        --reference)
            REFERENCE=${2:?missing reference endpoint}
            shift 2
            ;;
        --candidate)
            CANDIDATE=${2:?missing candidate endpoint}
            shift 2
            ;;
        --no-host-tests)
            RUN_HOST_TESTS=false
            shift
            ;;
        --no-netns-tests)
            RUN_NETWORK_NAMESPACE_TESTS=false
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

for command in cargo git make python3 sha256sum; do
    command -v "$command" >/dev/null || {
        printf 'Required command is missing: %s\n' "$command" >&2
        exit 2
    }
done

WORK="$(mktemp -d -t resolved-rs-certify.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$(dirname "$OUTPUT")"
RESULTS="$WORK/results.tsv"
: >"$RESULTS"

record() {
    local gate=$1
    local status=$2
    local detail=$3
    printf '%s\t%s\t%s\n' "$gate" "$status" "$detail" >>"$RESULTS"
}

run_gate() {
    local gate=$1
    shift
    local log="$WORK/${gate//[^A-Za-z0-9_.-]/_}.log"
    if "$@" >"$log" 2>&1; then
        record "$gate" pass "$log"
    else
        record "$gate" fail "$log"
        return 1
    fi
}

SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
BASELINE_COMMIT="$(cat "$ROOT/compat/upstream-systemd/commit" 2>/dev/null || true)"
BASELINE_RELEASE="$(cat "$ROOT/compat/upstream-systemd/release" 2>/dev/null || true)"

if git -C "$ROOT" diff --quiet && git -C "$ROOT" diff --cached --quiet; then
    record source-clean pass clean
else
    record source-clean fail dirty
fi

if [[ -n $BASELINE_COMMIT && -n $BASELINE_RELEASE ]] && \
   [[ -s "$ROOT/compat/upstream-systemd/manifest.sha256" ]]; then
    record upstream-baseline pass "$BASELINE_RELEASE:$BASELINE_COMMIT"
else
    record upstream-baseline fail missing
fi

run_gate rust-format cargo fmt --manifest-path "$ROOT/Cargo.toml" --all -- --check || true
run_gate native make -C "$ROOT" check-native || true
run_gate packaging make -C "$ROOT" check-packaging || true
run_gate nss make -C "$ROOT" check-nss || true
run_gate rust-clippy cargo clippy --manifest-path "$ROOT/Cargo.toml" \
    --all-targets --all-features --locked -- -D warnings || true
run_gate rust-tests cargo test --manifest-path "$ROOT/Cargo.toml" \
    --all-targets --all-features --locked || true
run_gate release-build cargo build --manifest-path "$ROOT/Cargo.toml" \
    --release --all-features --locked || true

if [[ -x $BINARY && -x $CLIENT ]]; then
    record release-binaries pass present
    BINARY_SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
    CLIENT_SHA256="$(sha256sum "$CLIENT" | awk '{print $1}')"
else
    record release-binaries fail missing
    BINARY_SHA256=""
    CLIENT_SHA256=""
fi

if [[ $RUN_NETWORK_NAMESPACE_TESTS == true ]] && command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
    run_gate live-mdns python3 "$ROOT/tests/live-mdns.py" "$BINARY" || true
    run_gate live-mdns-responder python3 "$ROOT/tests/live-mdns-responder.py" "$BINARY" || true
    run_gate live-dnssd python3 "$ROOT/tests/live-dnssd.py" "$BINARY" || true
else
    record live-mdns skip disabled-or-no-sudo
    record live-mdns-responder skip disabled-or-no-sudo
    record live-dnssd skip disabled-or-no-sudo
fi

PREFLIGHT_ARCHIVE="$WORK/preflight.tar.gz"
if [[ $RUN_HOST_TESTS == true ]] && [[ -x $BINARY && -x $CLIENT ]]; then
    run_gate host-differential \
        bash "$ROOT/scripts/preflight-replacement.sh" \
        --reference "$REFERENCE" \
        --candidate "$CANDIDATE" \
        --binary "$BINARY" \
        --client "$CLIENT" \
        --output "$PREFLIGHT_ARCHIVE" \
        --no-build || true
else
    record host-differential skip disabled
fi

UPSTREAM_PROOF="$ROOT/compat/upstream-systemd/proofs/TEST-75-RESOLVED.json"
SECURITY_PROOF="$ROOT/compat/upstream-systemd/proofs/security.json"
BOOT_PROOF="$ROOT/compat/upstream-systemd/proofs/boot-replacement.json"

verify_proof() {
    local gate=$1
    local path=$2
    if [[ ! -s $path ]]; then
        record "$gate" fail missing
        return
    fi
    if python3 - "$path" "$SOURCE_COMMIT" "$BASELINE_COMMIT" <<'PY'
import json
import sys

path, source, baseline = sys.argv[1:]
data = json.load(open(path, encoding="utf-8"))
if data.get("result") != "pass":
    raise SystemExit(1)
if data.get("source_commit") != source:
    raise SystemExit(1)
if data.get("upstream_commit") != baseline:
    raise SystemExit(1)
PY
    then
        record "$gate" pass "$path"
    else
        record "$gate" fail stale-or-invalid
    fi
}

verify_proof upstream-test-75 "$UPSTREAM_PROOF"
verify_proof security-suite "$SECURITY_PROOF"
verify_proof boot-replacement "$BOOT_PROOF"

python3 - \
    "$RESULTS" "$OUTPUT" "$SOURCE_COMMIT" "$SOURCE_TREE" \
    "$BASELINE_RELEASE" "$BASELINE_COMMIT" "$BINARY" "$BINARY_SHA256" \
    "$CLIENT" "$CLIENT_SHA256" "$PREFLIGHT_ARCHIVE" <<'PY'
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys

(
    results_path,
    output_path,
    source_commit,
    source_tree,
    upstream_release,
    upstream_commit,
    binary_path,
    binary_sha256,
    client_path,
    client_sha256,
    preflight_archive,
) = sys.argv[1:]

gates = []
for raw in Path(results_path).read_text(encoding="utf-8").splitlines():
    name, status, detail = raw.split("\t", 2)
    gates.append({"name": name, "status": status, "detail": detail})
certified = bool(gates) and all(gate["status"] == "pass" for gate in gates)
report = {
    "schema": 1,
    "certified": certified,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "source_commit": source_commit,
    "source_tree": source_tree,
    "upstream_release": upstream_release,
    "upstream_commit": upstream_commit,
    "binary": {"path": str(Path(binary_path).resolve()), "sha256": binary_sha256},
    "client": {"path": str(Path(client_path).resolve()), "sha256": client_sha256},
    "preflight_archive": (
        str(Path(preflight_archive).resolve()) if Path(preflight_archive).exists() else None
    ),
    "gates": gates,
}
Path(output_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(0 if certified else 1)
PY
