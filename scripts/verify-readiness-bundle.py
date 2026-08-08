#!/usr/bin/env python3
"""Verify a portable replacement-readiness certificate and its artifacts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


class BundleError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_artifact(
    certificate: Path, entry: dict[str, Any], label: str
) -> tuple[Path, str]:
    expected = entry.get("sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise BundleError(f"{label} hash is missing or invalid")
    relative = entry.get("artifact_path")
    if isinstance(relative, str) and relative:
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise BundleError(f"{label} artifact path is unsafe")
        candidate = (certificate.parent / relative_path).resolve()
        parent = certificate.parent.resolve()
        if candidate != parent and parent not in candidate.parents:
            raise BundleError(f"{label} artifact escapes the readiness bundle")
    else:
        original = entry.get("path")
        if not isinstance(original, str) or not original:
            raise BundleError(f"{label} artifact path is missing")
        candidate = Path(original).resolve()
    if not candidate.is_file():
        raise BundleError(f"{label} artifact is missing: {candidate}")
    actual = sha256(candidate)
    if actual != expected:
        raise BundleError(
            f"{label} artifact hash mismatch: expected {expected}, got {actual}"
        )
    return candidate, expected


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--maximum-age", type=int, default=86400)
    parser.add_argument("--shell-values", action="store_true")
    return parser.parse_args()


def main() -> int:
    options = arguments()
    if options.maximum_age <= 0:
        raise BundleError("maximum certificate age must be positive")
    certificate = options.certificate.resolve()
    try:
        data = json.loads(certificate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError(f"cannot read certificate: {error}") from error
    if not isinstance(data, dict) or data.get("schema") != 2:
        raise BundleError("unsupported certificate schema")
    if data.get("certified") is not True:
        raise BundleError("certificate is not certified")
    gates = data.get("gates")
    if not isinstance(gates, list) or not gates:
        raise BundleError("certificate contains no gates")
    if any(not isinstance(gate, dict) or gate.get("status") != "pass" for gate in gates):
        raise BundleError("certificate contains a nonpassing gate")

    try:
        generated = datetime.fromisoformat(str(data["generated_at"]))
    except (KeyError, ValueError) as error:
        raise BundleError("certificate timestamp is invalid") from error
    if generated.tzinfo is None:
        raise BundleError("certificate timestamp has no timezone")
    age = (datetime.now(timezone.utc) - generated.astimezone(timezone.utc)).total_seconds()
    if age < -300 or age > options.maximum_age:
        raise BundleError(
            f"certificate age {age:.0f}s is outside the allowed window"
        )

    source_commit = data.get("source_commit")
    source_tree = data.get("source_tree")
    upstream_commit = data.get("upstream_commit")
    for label, value in (
        ("source commit", source_commit),
        ("source tree", source_tree),
        ("upstream commit", upstream_commit),
    ):
        if (
            not isinstance(value, str)
            or len(value) != 40
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise BundleError(f"{label} is invalid")

    binary_entry = data.get("binary")
    client_entry = data.get("client")
    if not isinstance(binary_entry, dict) or not isinstance(client_entry, dict):
        raise BundleError("certificate binary metadata is incomplete")
    binary, binary_hash = resolve_artifact(certificate, binary_entry, "daemon")
    client, client_hash = resolve_artifact(certificate, client_entry, "client")

    if options.shell_values:
        for value in (
            source_commit,
            source_tree,
            str(binary),
            binary_hash,
            str(client),
            client_hash,
            upstream_commit,
        ):
            print(value)
    else:
        print(
            json.dumps(
                {
                    "certified": True,
                    "certificate": str(certificate),
                    "age_seconds": int(age),
                    "source_commit": source_commit,
                    "source_tree": source_tree,
                    "upstream_commit": upstream_commit,
                    "binary": {"path": str(binary), "sha256": binary_hash},
                    "client": {"path": str(client), "sha256": client_hash},
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, BundleError) as error:
        print(f"verify-readiness-bundle: {error}", file=sys.stderr)
        raise SystemExit(1) from error
