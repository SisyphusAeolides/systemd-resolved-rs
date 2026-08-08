#!/usr/bin/env python3
"""Validate external replacement proofs against the exact source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


class ProofValidationError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProofValidationError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise ProofValidationError(f"JSON root is not an object: {path}")
    return value


def locate_artifact(
    proof: Path,
    proof_directory: Path,
    gate: str,
    artifact: dict[str, Any],
) -> Path:
    original = artifact.get("path")
    name = artifact.get("name")
    if not name and original:
        name = Path(str(original)).name
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise ProofValidationError("proof artifact name is invalid")
    candidates = [
        proof.parent / name,
        proof_directory / "artifacts" / gate / name,
    ]
    if isinstance(original, str) and original:
        candidates.append(Path(original))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise ProofValidationError(f"proof artifact is missing: {name}")


def verify_artifacts(
    proof: Path,
    proof_directory: Path,
    gate: str,
    payload: dict[str, Any],
) -> dict[str, Path]:
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ProofValidationError("proof contains no artifacts")
    located: dict[str, Path] = {}
    for raw in artifacts:
        if not isinstance(raw, dict):
            raise ProofValidationError("proof artifact entry is not an object")
        path = locate_artifact(proof, proof_directory, gate, raw)
        expected_size = raw.get("size")
        expected_hash = raw.get("sha256")
        if not isinstance(expected_size, int) or expected_size < 0:
            raise ProofValidationError(f"artifact size is invalid: {path}")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise ProofValidationError(f"artifact hash is invalid: {path}")
        if path.stat().st_size != expected_size:
            raise ProofValidationError(f"artifact size mismatch: {path}")
        actual_hash = sha256(path)
        if actual_hash != expected_hash:
            raise ProofValidationError(f"artifact hash mismatch: {path}")
        located[path.name] = path
    return located


def metadata(payload: dict[str, Any]) -> dict[str, str]:
    value = payload.get("metadata")
    if not isinstance(value, dict):
        raise ProofValidationError("proof metadata is missing")
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        raise ProofValidationError("proof metadata must contain strings")
    return value


def require_artifact(located: dict[str, Path], name: str) -> Path:
    try:
        return located[name]
    except KeyError as error:
        raise ProofValidationError(f"required proof artifact is absent: {name}") from error


def validate_upstream(
    payload: dict[str, Any], located: dict[str, Path], upstream_commit: str
) -> None:
    values = metadata(payload)
    if values.get("suite") != "TEST-75-RESOLVED":
        raise ProofValidationError("upstream proof names the wrong suite")
    if values.get("unmodified-recorded-files") != "true":
        raise ProofValidationError("upstream proof does not attest unmodified recorded files")
    evidence = load_json(require_artifact(located, "evidence.json"))
    if evidence.get("suite") != "TEST-75-RESOLVED":
        raise ProofValidationError("upstream evidence names the wrong suite")
    if evidence.get("unmodified_recorded_upstream_files") is not True:
        raise ProofValidationError("upstream test hashes were not preserved")
    if evidence.get("upstream_commit") != upstream_commit:
        raise ProofValidationError("upstream evidence uses another baseline")
    marker = evidence.get("runtime_marker")
    if not isinstance(marker, str) or not marker.startswith("RESOLVED_RS_TEST_75_"):
        raise ProofValidationError("candidate runtime marker is missing")
    require_artifact(located, "TEST-75-RESOLVED.log")


def validate_security(payload: dict[str, Any], located: dict[str, Path]) -> None:
    values = metadata(payload)
    required = {"fuzz", "asan", "ubsan", "miri", "tsan", "valgrind"}
    profiles = {
        item.strip()
        for item in values.get("profiles", "").split(",")
        if item.strip()
    }
    if profiles != required:
        raise ProofValidationError(
            "security proof profiles differ: " + repr(sorted(profiles))
        )
    evidence = load_json(require_artifact(located, "security-evidence.json"))
    if evidence.get("missing") != []:
        raise ProofValidationError("security evidence still has missing categories")
    if set(evidence.get("required_categories", [])) != required:
        raise ProofValidationError("security evidence category set differs")
    matched = evidence.get("matched")
    if not isinstance(matched, dict):
        raise ProofValidationError("security evidence has no matched jobs")
    for category in required:
        values = matched.get(category)
        if not isinstance(values, list) or not values:
            raise ProofValidationError(f"security category has no successful job: {category}")
        if any(item.get("head_sha") is None for item in values if isinstance(item, dict)):
            raise ProofValidationError(f"security category evidence is malformed: {category}")


def validate_boot(
    payload: dict[str, Any], located: dict[str, Path], upstream_commit: str
) -> None:
    values = metadata(payload)
    if values.get("environment") != "qemu":
        raise ProofValidationError("boot proof did not use QEMU")
    if values.get("boot-count") != "2":
        raise ProofValidationError("boot proof did not complete exactly two candidate boots")
    if values.get("rollback-verified") != "true":
        raise ProofValidationError("boot proof did not verify rollback")
    evidence = load_json(require_artifact(located, "evidence.json"))
    if evidence.get("environment") != "qemu":
        raise ProofValidationError("boot evidence did not use QEMU")
    if evidence.get("boot_count") != 2:
        raise ProofValidationError("boot evidence count differs")
    if evidence.get("candidate_healthy_each_boot") is not True:
        raise ProofValidationError("candidate was not healthy on every boot")
    if evidence.get("rollback_verified") is not True:
        raise ProofValidationError("rollback did not pass")
    if evidence.get("upstream_commit") != upstream_commit:
        raise ProofValidationError("boot evidence uses another baseline")
    require_artifact(located, "mkosi-build.log")
    require_artifact(located, "qemu-console.log")


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--upstream-commit", required=True)
    parser.add_argument("--proof-directory", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    options = arguments()
    proof = options.proof.resolve()
    proof_directory = options.proof_directory.resolve()
    payload = load_json(proof)
    if payload.get("schema") != 1:
        raise ProofValidationError("unsupported proof schema")
    if payload.get("gate") != options.gate:
        raise ProofValidationError("proof gate mismatch")
    if payload.get("result") != "pass":
        raise ProofValidationError("proof did not pass")
    if payload.get("source_tree") != options.source_tree:
        raise ProofValidationError("proof source tree is stale")
    if payload.get("upstream_commit") != options.upstream_commit:
        raise ProofValidationError("proof upstream baseline is stale")

    located = verify_artifacts(proof, proof_directory, options.gate, payload)
    if options.gate == "upstream-test-75":
        validate_upstream(payload, located, options.upstream_commit)
    elif options.gate == "security-suite":
        validate_security(payload, located)
    elif options.gate == "boot-replacement":
        validate_boot(payload, located, options.upstream_commit)
    else:
        raise ProofValidationError(f"unknown proof gate: {options.gate}")

    for name, path in sorted(located.items()):
        print(f"verified {name}: {path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ProofValidationError) as error:
        print(f"validate-replacement-proof: {error}", file=sys.stderr)
        raise SystemExit(1) from error
