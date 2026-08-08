#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$ROOT/target/replacement-certification.json"
PROOF_DIR="$ROOT/target/replacement-proofs"
BINARY="$ROOT/target/release/systemd-resolved"
CLIENT="$ROOT/target/release/resolvectl"
REFERENCE="127.0.0.53:53"
CANDIDATE="127.0.0.1:10553"
RUN_HOST_TESTS=true
RUN_NETWORK_NAMESPACE_TESTS=true

usage() {
    cat <<'EOF'
Usage: scripts/certify-replacement.sh [OPTIONS]

Creates a fail-closed replacement certificate. Certification requires a clean
Git tree, the immutable upstream baseline, every local build/live gate, and
external proofs for the pinned upstream resolver suite, the full security
suite, and a rebooted replacement VM.

Options:
  --output PATH             Certificate destination
  --proof-directory PATH    External proof directory
  --binary PATH             Release daemon binary
  --client PATH             Release resolvectl binary
  --reference HOST:PORT     Existing resolver for shadow comparison
  --candidate HOST:PORT     Candidate shadow endpoint
  --no-host-tests           Record host differential testing as failed
  --no-netns-tests          Record live mDNS/DNS-SD testing as failed
  -h, --help                Show this help
EOF
}

while (($#)); do
    case "$1" in
        --output)
            OUTPUT=${2:?missing output path}
            shift 2
            ;;
        --proof-directory)
            PROOF_DIR=${2:?missing proof directory}
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

for command in cargo git make python3 readlink sha256sum; do
    command -v "$command" >/dev/null || {
        printf 'Required command is missing: %s\n' "$command" >&2
        exit 2
    }
done

OUTPUT="$(readlink -m "$OUTPUT")"
PROOF_DIR="$(readlink -m "$PROOF_DIR")"
REPORT_DIR="${OUTPUT%.json}.d"
LOG_DIR="$REPORT_DIR/logs"
ARTIFACT_DIR="$REPORT_DIR/artifacts"
RESULTS="$REPORT_DIR/gates.tsv"
rm -rf "$REPORT_DIR"
mkdir -p "$LOG_DIR" "$ARTIFACT_DIR" "$(dirname "$OUTPUT")"
: >"$RESULTS"

record() {
    local gate=$1
    local status=$2
    local detail=$3
    detail=${detail//$'\t'/ }
    detail=${detail//$'\n'/ }
    printf '%s\t%s\t%s\n' "$gate" "$status" "$detail" >>"$RESULTS"
}

run_gate() {
    local gate=$1
    shift
    local log="$LOG_DIR/${gate//[^A-Za-z0-9_.-]/_}.log"
    {
        printf '$'
        printf ' %q' "$@"
        printf '\n'
        "$@"
    } >"$log" 2>&1
    local status=$?
    if ((status == 0)); then
        record "$gate" pass "$log"
    else
        record "$gate" fail "$log (exit $status)"
    fi
    return 0
}

SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
BASELINE_COMMIT="$(cat "$ROOT/compat/upstream-systemd/commit" 2>/dev/null || true)"
BASELINE_RELEASE="$(cat "$ROOT/compat/upstream-systemd/release" 2>/dev/null || true)"

if [[ -z $(git -C "$ROOT" status --porcelain=v1 --untracked-files=all) ]]; then
    record source-clean pass clean
else
    git -C "$ROOT" status --porcelain=v1 --untracked-files=all >"$LOG_DIR/source-clean.log"
    record source-clean fail "$LOG_DIR/source-clean.log"
fi

if [[ $SOURCE_COMMIT =~ ^[0-9a-f]{40}$ && $SOURCE_TREE =~ ^[0-9a-f]{40}$ ]]; then
    record source-identity pass "$SOURCE_COMMIT:$SOURCE_TREE"
else
    record source-identity fail invalid
fi

run_gate upstream-baseline \
    bash "$ROOT/scripts/verify-upstream-resolved-baseline.sh"
run_gate rust-format \
    cargo fmt --manifest-path "$ROOT/Cargo.toml" --all -- --check
run_gate native \
    make -C "$ROOT" check-native
run_gate packaging \
    make -C "$ROOT" check-packaging
run_gate nss \
    make -C "$ROOT" check-nss
run_gate rust-clippy \
    cargo clippy --manifest-path "$ROOT/Cargo.toml" \
    --all-targets --all-features --locked -- -D warnings
run_gate rust-tests \
    cargo test --manifest-path "$ROOT/Cargo.toml" \
    --all-targets --all-features --locked
run_gate release-build \
    cargo build --manifest-path "$ROOT/Cargo.toml" \
    --release --all-features --locked

BINARY_SHA256=""
CLIENT_SHA256=""
if [[ -x $BINARY && -x $CLIENT ]]; then
    BINARY="$(readlink -f "$BINARY")"
    CLIENT="$(readlink -f "$CLIENT")"
    BINARY_SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
    CLIENT_SHA256="$(sha256sum "$CLIENT" | awk '{print $1}')"
    cp -a "$BINARY" "$ARTIFACT_DIR/systemd-resolved"
    cp -a "$CLIENT" "$ARTIFACT_DIR/resolvectl"
    record release-binaries pass "$BINARY_SHA256:$CLIENT_SHA256"
else
    record release-binaries fail missing
fi

run_gate live-dns \
    python3 "$ROOT/tests/live-dns.py" "$BINARY" "$CLIENT"
run_gate live-dbus \
    bash "$ROOT/tests/dbus-introspection.sh" "$BINARY"

if [[ $RUN_NETWORK_NAMESPACE_TESTS == true ]] \
    && command -v sudo >/dev/null \
    && sudo -n true >/dev/null 2>&1; then
    run_gate live-mdns \
        python3 "$ROOT/tests/live-mdns.py" "$BINARY"
    run_gate live-mdns-responder \
        python3 "$ROOT/tests/live-mdns-responder.py" "$BINARY"
    run_gate live-dnssd \
        python3 "$ROOT/tests/live-dnssd.py" "$BINARY"
else
    record live-mdns fail disabled-or-passwordless-sudo-unavailable
    record live-mdns-responder fail disabled-or-passwordless-sudo-unavailable
    record live-dnssd fail disabled-or-passwordless-sudo-unavailable
fi

PREFLIGHT_ARCHIVE="$ARTIFACT_DIR/preflight.tar.gz"
if [[ $RUN_HOST_TESTS == true && -x $BINARY && -x $CLIENT ]]; then
    run_gate host-differential \
        bash "$ROOT/scripts/preflight-replacement.sh" \
        --reference "$REFERENCE" \
        --candidate "$CANDIDATE" \
        --binary "$BINARY" \
        --client "$CLIENT" \
        --output "$PREFLIGHT_ARCHIVE" \
        --no-build
else
    record host-differential fail disabled-or-binary-missing
fi

verify_proof() {
    local gate=$1
    local proof="$PROOF_DIR/$gate.json"
    local log="$LOG_DIR/proof-$gate.log"
    if [[ ! -s $proof ]]; then
        printf 'Missing proof: %s\n' "$proof" >"$log"
        record "$gate" fail "$log"
        return
    fi
    if python3 - \
        "$proof" "$gate" "$SOURCE_TREE" "$BASELINE_COMMIT" "$PROOF_DIR" <<'PY' \
        >"$log" 2>&1
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

proof_path = Path(sys.argv[1]).resolve()
gate = sys.argv[2]
source_tree = sys.argv[3]
upstream_commit = sys.argv[4]
proof_directory = Path(sys.argv[5]).resolve()
data = json.loads(proof_path.read_text(encoding="utf-8"))
if data.get("schema") != 1:
    raise SystemExit("unsupported proof schema")
if data.get("gate") != gate:
    raise SystemExit("proof gate mismatch")
if data.get("result") != "pass":
    raise SystemExit("proof did not pass")
if data.get("source_tree") != source_tree:
    raise SystemExit("proof source tree is stale")
if data.get("upstream_commit") != upstream_commit:
    raise SystemExit("proof upstream baseline is stale")
artifacts = data.get("artifacts")
if not isinstance(artifacts, list) or not artifacts:
    raise SystemExit("proof contains no artifacts")
for artifact in artifacts:
    expected_name = artifact.get("name") or Path(str(artifact.get("path", ""))).name
    expected_hash = artifact.get("sha256")
    expected_size = artifact.get("size")
    if not expected_name or not expected_hash or not isinstance(expected_size, int):
        raise SystemExit("proof artifact metadata is incomplete")
    candidates = [
        proof_path.parent / expected_name,
        proof_directory / "artifacts" / gate / expected_name,
    ]
    original = artifact.get("path")
    if original:
        candidates.append(Path(str(original)))
    actual = next((candidate for candidate in candidates if candidate.is_file()), None)
    if actual is None:
        raise SystemExit(f"proof artifact is missing: {expected_name}")
    if actual.stat().st_size != expected_size:
        raise SystemExit(f"proof artifact size mismatch: {actual}")
    digest = hashlib.sha256(actual.read_bytes()).hexdigest()
    if digest != expected_hash:
        raise SystemExit(f"proof artifact hash mismatch: {actual}")
    print(f"verified {actual}: {digest}")
PY
    then
        cp -a "$proof" "$ARTIFACT_DIR/$gate.json"
        record "$gate" pass "$proof"
    else
        record "$gate" fail "$log"
    fi
}

verify_proof upstream-test-75
verify_proof security-suite
verify_proof boot-replacement

if [[ -z $(git -C "$ROOT" status --porcelain=v1 --untracked-files=all) ]]; then
    record source-clean-after-tests pass clean
else
    git -C "$ROOT" status --porcelain=v1 --untracked-files=all \
        >"$LOG_DIR/source-clean-after-tests.log"
    record source-clean-after-tests fail "$LOG_DIR/source-clean-after-tests.log"
fi

python3 - \
    "$RESULTS" "$OUTPUT" "$REPORT_DIR" "$SOURCE_COMMIT" "$SOURCE_TREE" \
    "$BASELINE_RELEASE" "$BASELINE_COMMIT" "$BINARY" "$BINARY_SHA256" \
    "$CLIENT" "$CLIENT_SHA256" "$PREFLIGHT_ARCHIVE" <<'PY'
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

(
    results_path,
    output_path,
    report_directory,
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
required = {gate["name"] for gate in gates}
expected = {
    "source-clean",
    "source-identity",
    "upstream-baseline",
    "rust-format",
    "native",
    "packaging",
    "nss",
    "rust-clippy",
    "rust-tests",
    "release-build",
    "release-binaries",
    "live-dns",
    "live-dbus",
    "live-mdns",
    "live-mdns-responder",
    "live-dnssd",
    "host-differential",
    "upstream-test-75",
    "security-suite",
    "boot-replacement",
    "source-clean-after-tests",
}
missing = sorted(expected - required)
if missing:
    gates.append(
        {
            "name": "certificate-schema",
            "status": "fail",
            "detail": "missing gates: " + ", ".join(missing),
        }
    )
certified = bool(gates) and not missing and all(
    gate["status"] == "pass" for gate in gates
)
report = {
    "schema": 2,
    "certified": certified,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "source_commit": source_commit,
    "source_tree": source_tree,
    "upstream_release": upstream_release,
    "upstream_commit": upstream_commit,
    "binary": {"path": binary_path, "sha256": binary_sha256},
    "client": {"path": client_path, "sha256": client_sha256},
    "report_directory": str(Path(report_directory).resolve()),
    "preflight_archive": (
        str(Path(preflight_archive).resolve()) if Path(preflight_archive).is_file() else None
    ),
    "gates": gates,
}
encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
Path(output_path).write_text(encoded, encoding="utf-8")
print(encoded, end="")
raise SystemExit(0 if certified else 1)
PY
