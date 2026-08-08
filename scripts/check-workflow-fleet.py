#!/usr/bin/env python3
"""Reject accidental and obsolete GitHub Actions launchers.

The repository previously accumulated one-shot, self-mutating workflows that
were meant to delete themselves after landing a tested change. Invalid or
stranded launchers caused every push to show unrelated red workflow runs. Keep
only the permanent workflow fleet here so additions and removals are explicit.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"

PERMANENT_WORKFLOWS = {
    "build-and-test.yml",
    "dnssd-live.yml",
    "mdns-duplex.yml",
    "mdns-live.yml",
    "mdns-responder-live.yml",
    "pin-upstream-resolved.yml",
    "replacement-boot-proof.yml",
    "replacement-full-certification.yml",
    "replacement-readiness-certificate.yml",
    "replacement-security-gates.yml",
    "replacement-security-proof.yml",
    "replacement-upstream-test-75.yml",
    "reproducible-release.yml",
    "upstream-surface-audit.yml",
    "verify-upstream-baseline.yml",
}

OBSOLETE_PREFIXES = ("finalize-", "fix-", "integrate-", "land-", "reconcile-")
TOP_LEVEL_KEYS = ("name", "on", "jobs")


def fail(message: str) -> None:
    print(f"workflow fleet check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def top_level_key_present(text: str, key: str) -> bool:
    return re.search(rf"(?m)^{re.escape(key)}\s*:", text) is not None


def main() -> None:
    if not WORKFLOW_DIR.is_dir():
        fail(f"missing workflow directory: {WORKFLOW_DIR}")

    paths = sorted(WORKFLOW_DIR.glob("*.yml"))
    actual = {path.name for path in paths}
    missing = sorted(PERMANENT_WORKFLOWS - actual)
    unexpected = sorted(actual - PERMANENT_WORKFLOWS)
    if missing:
        fail("missing permanent workflows: " + ", ".join(missing))
    if unexpected:
        fail("unexpected workflows: " + ", ".join(unexpected))

    obsolete = sorted(name for name in actual if name.startswith(OBSOLETE_PREFIXES))
    if obsolete:
        fail("obsolete integration launchers remain: " + ", ".join(obsolete))

    for path in paths:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            fail(f"empty workflow: {path.name}")
        if "\t" in text:
            fail(f"tab indentation in {path.name}")
        for key in TOP_LEVEL_KEYS:
            if not top_level_key_present(text, key):
                fail(f"{path.name} is missing top-level {key!r}")
        if "git push origin HEAD:main" in text and path.name != "pin-upstream-resolved.yml":
            fail(f"self-mutating permanent workflow: {path.name}")

    print(f"workflow fleet check passed: {len(paths)} permanent workflows")


if __name__ == "__main__":
    main()
