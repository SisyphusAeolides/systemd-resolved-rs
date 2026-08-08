#!/usr/bin/env python3
"""Import a downloaded proof directory or ZIP into the certification layout."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


class ImportError(RuntimeError):
    pass


GATES = {"upstream-test-75", "security-suite", "boot-replacement"}


def extract_zip(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            item = Path(info.filename)
            if item.is_absolute() or ".." in item.parts:
                raise ImportError(f"unsafe ZIP member: {info.filename}")
            if info.is_dir():
                continue
            target = (destination / item).resolve()
            if destination.resolve() not in target.parents:
                raise ImportError(f"ZIP member escapes destination: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as input_stream, target.open("wb") as output_stream:
                shutil.copyfileobj(input_stream, output_stream)


def proof_candidates(root: Path) -> list[tuple[Path, dict[str, object]]]:
    output = []
    for path in sorted(root.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (
            isinstance(payload, dict)
            and payload.get("schema") == 1
            and payload.get("gate") in GATES
            and payload.get("result") in {"pass", "fail"}
        ):
            output.append((path, payload))
    return output


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument(
        "--proof-directory",
        type=Path,
        default=Path("target/replacement-proofs"),
    )
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    return parser.parse_args()


def main() -> int:
    options = arguments()
    root = options.root.resolve()
    source = options.source.resolve()
    proof_directory = options.proof_directory
    if not proof_directory.is_absolute():
        proof_directory = root / proof_directory
    proof_directory = proof_directory.resolve()
    if not source.exists():
        raise ImportError(f"proof source does not exist: {source}")

    with tempfile.TemporaryDirectory(prefix="resolved-proof-import-") as temporary_name:
        temporary = Path(temporary_name)
        extracted = temporary / "extracted"
        extracted.mkdir()
        if source.is_dir():
            for path in source.rglob("*"):
                if not path.is_file():
                    continue
                relative = path.relative_to(source)
                target = extracted / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
        elif zipfile.is_zipfile(source):
            extract_zip(source, extracted)
        else:
            raise ImportError("proof source must be a directory or ZIP archive")

        candidates = proof_candidates(extracted)
        if len(candidates) != 1:
            raise ImportError(
                f"expected exactly one replacement proof, found {len(candidates)}"
            )
        proof, payload = candidates[0]
        gate = str(payload["gate"])
        if payload.get("result") != "pass":
            raise ImportError(f"proof did not pass: {gate}")
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ImportError("proof contains no artifacts")

        staged = temporary / "staged"
        artifact_stage = staged / "artifacts" / gate
        artifact_stage.mkdir(parents=True)
        names: set[str] = set()
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise ImportError("proof artifact entry is malformed")
            original = artifact.get("path")
            name = artifact.get("name") or Path(str(original or "")).name
            if not isinstance(name, str) or Path(name).name != name or not name:
                raise ImportError("proof artifact name is invalid")
            if name in names:
                raise ImportError(f"duplicate proof artifact name: {name}")
            names.add(name)
            matches = [path for path in extracted.rglob(name) if path.is_file()]
            if len(matches) != 1:
                raise ImportError(
                    f"expected one extracted artifact named {name}, found {len(matches)}"
                )
            shutil.copy2(matches[0], artifact_stage / name)
        proof_stage = staged / f"{gate}.json"
        shutil.copy2(proof, proof_stage)

        source_tree = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()
        upstream_commit = (
            root / "compat" / "upstream-systemd" / "commit"
        ).read_text(encoding="ascii").strip()
        subprocess.run(
            [
                sys.executable,
                str(root / "scripts" / "validate-replacement-proof.py"),
                "--proof",
                str(proof_stage),
                "--gate",
                gate,
                "--source-tree",
                source_tree,
                "--upstream-commit",
                upstream_commit,
                "--proof-directory",
                str(staged),
            ],
            check=True,
        )

        proof_directory.mkdir(parents=True, exist_ok=True)
        destination_artifacts = proof_directory / "artifacts" / gate
        destination_artifacts.parent.mkdir(parents=True, exist_ok=True)
        temporary_artifacts = proof_directory / "artifacts" / f".{gate}.new"
        if temporary_artifacts.exists():
            shutil.rmtree(temporary_artifacts)
        shutil.copytree(artifact_stage, temporary_artifacts)
        if destination_artifacts.exists():
            shutil.rmtree(destination_artifacts)
        temporary_artifacts.replace(destination_artifacts)
        temporary_proof = proof_directory / f".{gate}.json.new"
        shutil.copy2(proof_stage, temporary_proof)
        temporary_proof.replace(proof_directory / f"{gate}.json")
        print(f"Imported and validated {gate} into {proof_directory}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ImportError, subprocess.CalledProcessError) as error:
        print(f"import-replacement-proof: {error}", file=sys.stderr)
        raise SystemExit(1) from error
