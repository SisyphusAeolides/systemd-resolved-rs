#!/usr/bin/env python3
"""Download and import replacement proof artifacts for one GitHub SHA."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request


class DownloadError(RuntimeError):
    pass


ARTIFACT_PREFIXES = {
    "upstream-test-75": "replacement-upstream-test-75-proof-",
    "security-suite": "replacement-security-proof-",
    "boot-replacement": "replacement-boot-proof-",
}


def api_request(url: str, token: str) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise DownloadError(f"GitHub response is not an object: {url}")
    return value


def download(url: str, token: str, output: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response, output.open("wb") as stream:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            stream.write(chunk)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--token", default=os.environ.get("GH_TOKEN"))
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    parser.add_argument(
        "--proof-directory", type=Path, default=Path("target/replacement-proofs")
    )
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    return parser.parse_args()


def main() -> int:
    options = arguments()
    if not options.repository or not options.sha or not options.token:
        raise DownloadError("repository, SHA, and token are required")
    if len(options.sha) != 40:
        raise DownloadError("SHA must be a full Git commit identifier")
    root = options.root.resolve()
    proof_directory = options.proof_directory
    if not proof_directory.is_absolute():
        proof_directory = root / proof_directory
    proof_directory = proof_directory.resolve()
    proof_directory.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="resolved-proof-download-") as temporary_name:
        temporary = Path(temporary_name)
        for gate, prefix in ARTIFACT_PREFIXES.items():
            name = prefix + options.sha
            query = urllib.parse.urlencode({"name": name, "per_page": 100})
            payload = api_request(
                f"{options.api_url}/repos/{options.repository}/actions/artifacts?{query}",
                options.token,
            )
            artifacts = [
                artifact
                for artifact in payload.get("artifacts", [])
                if isinstance(artifact, dict)
                and artifact.get("name") == name
                and artifact.get("expired") is False
            ]
            if not artifacts:
                raise DownloadError(f"no unexpired proof artifact exists for {gate} at {options.sha}")
            artifacts.sort(key=lambda value: str(value.get("created_at", "")), reverse=True)
            artifact = artifacts[0]
            workflow_run = artifact.get("workflow_run")
            if isinstance(workflow_run, dict):
                head_sha = workflow_run.get("head_sha")
                if head_sha is not None and head_sha != options.sha:
                    raise DownloadError(f"artifact run SHA mismatch for {gate}")
            archive_url = artifact.get("archive_download_url")
            if not isinstance(archive_url, str):
                raise DownloadError(f"artifact has no download URL for {gate}")
            archive = temporary / f"{gate}.zip"
            download(archive_url, options.token, archive)
            subprocess.run(
                [
                    sys.executable,
                    str(root / "scripts" / "import-replacement-proof.py"),
                    str(archive),
                    "--root",
                    str(root),
                    "--proof-directory",
                    str(proof_directory),
                ],
                check=True,
            )
    print(f"Downloaded and validated all replacement proofs for {options.sha}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, DownloadError, subprocess.CalledProcessError) as error:
        print(f"download-replacement-proofs: {error}", file=sys.stderr)
        raise SystemExit(1) from error
