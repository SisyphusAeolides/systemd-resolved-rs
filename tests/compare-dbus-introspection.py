#!/usr/bin/env python3
import json
import sys
import xml.etree.ElementTree as ET


def interface(path: str, name: str) -> ET.Element:
    root = ET.parse(path).getroot()
    candidates = [root] if root.tag == "interface" else root.findall("interface")
    for candidate in candidates:
        if candidate.get("name") == name:
            return candidate
    raise SystemExit(f"{path}: interface {name} not found")


def contract(element: ET.Element) -> dict[str, object]:
    methods = {}
    for method in element.findall("method"):
        methods[method.get("name")] = [
            (
                argument.get("name", ""),
                argument.get("type", ""),
                argument.get("direction", "in"),
            )
            for argument in method.findall("arg")
        ]
    properties = {
        prop.get("name"): (prop.get("type"), prop.get("access"))
        for prop in element.findall("property")
    }
    signals = {
        signal.get("name"): [
            (argument.get("name", ""), argument.get("type", ""))
            for argument in signal.findall("arg")
        ]
        for signal in element.findall("signal")
    }
    return {"methods": methods, "properties": properties, "signals": signals}


expected = contract(interface(sys.argv[1], sys.argv[3]))
actual = contract(interface(sys.argv[2], sys.argv[3]))
if expected != actual:
    print("EXPECTED")
    print(json.dumps(expected, indent=2, sort_keys=True))
    print("ACTUAL")
    print(json.dumps(actual, indent=2, sort_keys=True))
    raise SystemExit(1)
