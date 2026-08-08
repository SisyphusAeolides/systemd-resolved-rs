#!/usr/bin/env python3
"""Inventory resolver compatibility surfaces from the pinned systemd source."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any
import xml.etree.ElementTree as ET


class AuditError(RuntimeError):
    pass


def command(*arguments: str, cwd: Path | None = None) -> str:
    try:
        return subprocess.check_output(
            list(arguments),
            cwd=cwd,
            text=True,
            stderr=subprocess.PIPE,
        ).strip()
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() if error.stderr else str(error)
        raise AuditError(f"command failed: {' '.join(arguments)}: {detail}") from error


def snake_case(value: str) -> str:
    first = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first).lower()


def source_text(root: Path) -> str:
    parts = []
    for directory in (root / "src", root / "ffi", root / "nss"):
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.suffix not in {".rs", ".c", ".h", ".f90"} or not path.is_file():
                continue
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def xml_signature(member: ET.Element) -> dict[str, Any]:
    return {
        "name": member.attrib.get("name", ""),
        "kind": member.tag,
        "type": member.attrib.get("type"),
        "access": member.attrib.get("access"),
        "arguments": [
            {
                "name": argument.attrib.get("name"),
                "type": argument.attrib.get("type"),
                "direction": argument.attrib.get("direction"),
            }
            for argument in member.findall("arg")
        ],
    }


def dbus_interfaces(systemd: Path) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in sorted((systemd / "src" / "resolve").glob("*.xml")):
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            continue
        for interface in root.findall(".//interface"):
            name = interface.attrib.get("name")
            if not name or "resolve1" not in name:
                continue
            for kind in ("method", "property", "signal"):
                for member in interface.findall(kind):
                    signature = xml_signature(member)
                    signature["source"] = path.relative_to(systemd).as_posix()
                    output[name].append(signature)
    for values in output.values():
        values.sort(key=lambda item: (item["kind"], item["name"]))
    return dict(sorted(output.items()))


def varlink_surfaces(systemd: Path) -> dict[str, list[str]]:
    methods: set[str] = set()
    errors: set[str] = set()
    enums: set[str] = set()
    for path in sorted((systemd / "src" / "resolve").glob("varlink-*.c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        methods.update(
            re.findall(r"SD_VARLINK_DEFINE_METHOD\(\s*([A-Za-z0-9_]+)", text)
        )
        errors.update(
            re.findall(r"SD_VARLINK_DEFINE_ERROR\(\s*([A-Za-z0-9_.]+)", text)
        )
        enums.update(
            re.findall(r"SD_VARLINK_DEFINE_ENUM_TYPE\(\s*([A-Za-z0-9_]+)", text)
        )
    return {
        "methods": sorted(methods),
        "errors": sorted(errors),
        "enums": sorted(enums),
    }


def configuration_keys(systemd: Path) -> list[str]:
    keys: set[str] = set()
    for path in sorted((systemd / "src" / "resolve").glob("*gperf*")):
        text = path.read_text(encoding="utf-8", errors="replace")
        keys.update(re.findall(r"\bResolve\.([A-Za-z0-9]+)\b", text))
    return sorted(keys)


def resolvectl_verbs(systemd: Path) -> list[str]:
    verbs: set[str] = set()
    for name in ("resolvectl.c", "resolvectl.c.in", "resolve-tool.c"):
        path = systemd / "src" / "resolve" / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        verbs.update(
            value
            for value in re.findall(r'\{\s*"([a-z][a-z0-9-]+)"\s*,', text)
            if value not in {"help"}
        )
    return sorted(verbs)


def mentioned(text: str, name: str) -> bool:
    candidates = {
        name,
        snake_case(name),
        name.replace("-", "_"),
        name.lower(),
    }
    return any(candidate and candidate in text for candidate in candidates)


def audit(root: Path, systemd: Path) -> dict[str, Any]:
    local = source_text(root)
    dbus = dbus_interfaces(systemd)
    varlink = varlink_surfaces(systemd)
    config = configuration_keys(systemd)
    verbs = resolvectl_verbs(systemd)

    missing_dbus = []
    for interface, members in dbus.items():
        for member in members:
            if not mentioned(local, member["name"]):
                missing_dbus.append(
                    {
                        "interface": interface,
                        "kind": member["kind"],
                        "name": member["name"],
                    }
                )
    missing_varlink_methods = [
        name for name in varlink["methods"] if not mentioned(local, name)
    ]
    missing_varlink_errors = [
        name for name in varlink["errors"] if not mentioned(local, name)
    ]
    missing_configuration = [name for name in config if not mentioned(local, name)]
    missing_verbs = [name for name in verbs if not mentioned(local, name)]

    suspicious = []
    patterns = {
        "todo_macro": re.compile(r"\btodo!\s*\("),
        "unimplemented_macro": re.compile(r"\bunimplemented!\s*\("),
        "not_supported_error": re.compile(r"NotSupported|not supported", re.I),
        "stub_marker": re.compile(r"\bstub\b|implement .* later", re.I),
    }
    for path in sorted((root / "src").rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for category, pattern in patterns.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                suspicious.append(
                    {
                        "category": category,
                        "path": path.relative_to(root).as_posix(),
                        "line": line,
                        "excerpt": text[match.start() : match.start() + 100].splitlines()[0],
                    }
                )

    return {
        "schema": 1,
        "upstream_commit": command("git", "rev-parse", "HEAD", cwd=systemd),
        "source_tree": command("git", "rev-parse", "HEAD^{tree}", cwd=root),
        "dbus": dbus,
        "varlink": varlink,
        "configuration_keys": config,
        "resolvectl_verbs": verbs,
        "missing": {
            "dbus": missing_dbus,
            "varlink_methods": missing_varlink_methods,
            "varlink_errors": missing_varlink_errors,
            "configuration_keys": missing_configuration,
            "resolvectl_verbs": missing_verbs,
        },
        "suspicious_implementation_markers": suspicious,
        "counts": {
            "dbus_members": sum(len(values) for values in dbus.values()),
            "varlink_methods": len(varlink["methods"]),
            "varlink_errors": len(varlink["errors"]),
            "configuration_keys": len(config),
            "resolvectl_verbs": len(verbs),
            "missing_total": (
                len(missing_dbus)
                + len(missing_varlink_methods)
                + len(missing_varlink_errors)
                + len(missing_configuration)
                + len(missing_verbs)
            ),
        },
    }


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--systemd-tree", type=Path)
    parser.add_argument("--output", type=Path, default=Path("target/upstream-surface-audit.json"))
    parser.add_argument("--fail-on-missing", action="store_true")
    return parser.parse_args()


def main() -> int:
    options = arguments()
    root = options.root.resolve()
    baseline = root / "compat" / "upstream-systemd"
    commit = (baseline / "commit").read_text(encoding="ascii").strip()
    temporary: Path | None = None
    if options.systemd_tree:
        systemd = options.systemd_tree.resolve()
    else:
        temporary = Path(tempfile.mkdtemp(prefix="resolved-surface-audit-"))
        systemd = temporary / "systemd"
        command(
            "git",
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            "https://github.com/systemd/systemd.git",
            str(systemd),
        )
        command("git", "fetch", "--depth", "1", "origin", commit, cwd=systemd)
        command("git", "checkout", "--detach", commit, cwd=systemd)
    try:
        if command("git", "rev-parse", "HEAD", cwd=systemd) != commit:
            raise AuditError("systemd tree differs from the pinned commit")
        report = audit(root, systemd)
        output = options.output
        if not output.is_absolute():
            output = root / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(report["counts"], indent=2, sort_keys=True))
        if options.fail_on_missing and report["counts"]["missing_total"]:
            return 1
        return 0
    finally:
        if temporary:
            shutil.rmtree(temporary)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, OSError) as error:
        print(f"audit-upstream-resolver-surfaces: {error}", file=sys.stderr)
        raise SystemExit(2) from error
