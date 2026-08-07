#!/usr/bin/env python3
"""Write a cryptographically bound, external replacement-gate proof."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
from typing import Iterable


class ProofError(RuntimeError):
    pass


def git(root: Path, *arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *arguments],
            text=True,
            stderr=subprocess.PIPE,
        ).strip()
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() if error.stderr else str(error)
        raise ProofError(f"git {' '.join(arguments)} failed: {detail}") from error


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_entries(paths: Iterable[Path]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for path in paths:
        resolved = path.resolve()
        if not resolved.is_file():
            raise ProofError(f"artifact is not a file: {path}")
        output.append(
            {
                "path": str(resolved),
                "size": resolved.stat().st_size,
                "sha256": sha256(resolved),
            }
        )
    return output


def parse_metadata(values: list[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key:
            raise ProofError(f"metadata must use KEY=VALUE: {value}")
        if key in output:
            raise ProofError(f"duplicate metadata key: {key}")
        output[key] = item
    return output


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", required=True)
    parser.add_argument("--result", choices=("pass", "fail"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--upstream-commit")
    parser.add_argument("--source-tree")
    parser.add_argument("--source-commit")
    parser.add_argument("--artifact", action="append", type=Path, default=[])
    parser.add_argument("--metadata", action="append", default=[])
    parser.add_argument("--summary", default="")
    return parser.parse_args()


def main() -> int:
    options = arguments()
    root = options.root.resolve()
    if not (root / ".git").exists():
        raise ProofError(f"not a Git work tree: {root}")
    gate = options.gate.strip()
    if not gate or any(character.isspace() for character in gate):
        raise ProofError("gate must be a nonempty token without whitespace")

    source_commit = options.source_commit or git(root, "rev-parse", "HEAD")
    source_tree = options.source_tree or git(root, "rev-parse", "HEAD^{tree}")
    upstream_commit = options.upstream_commit
    if not upstream_commit:
        baseline = root / "compat" / "upstream-systemd" / "commit"
        if not baseline.is_file():
            raise ProofError("the pinned upstream commit is missing")
        upstream_commit = baseline.read_text(encoding="ascii").strip()

    for name, value in (
        ("source commit", source_commit),
        ("source tree", source_tree),
        ("upstream commit", upstream_commit),
    ):
        if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
            raise ProofError(f"invalid {name}: {value}")

    output = options.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 1,
        "gate": gate,
        "result": options.result,
        "summary": options.summary,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": source_commit,
        "source_tree": source_tree,
        "upstream_commit": upstream_commit,
        "host": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "ci": os.environ.get("CI") == "true",
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "github_repository": os.environ.get("GITHUB_REPOSITORY"),
            "github_sha": os.environ.get("GITHUB_SHA"),
        },
        "metadata": parse_metadata(options.metadata),
        "artifacts": artifact_entries(options.artifact),
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ProofError) as error:
        print(f"write-replacement-proof: {error}", file=sys.stderr)
        raise SystemExit(2) from error
