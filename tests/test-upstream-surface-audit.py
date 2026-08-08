#!/usr/bin/env python3
"""Regression tests for the pinned resolver surface inventory parsers."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit-upstream-resolver-surfaces.py"


def load_module():
    spec = importlib.util.spec_from_file_location("resolver_surface_audit", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    module = load_module()
    with tempfile.TemporaryDirectory(prefix="surface-audit-test-") as directory:
        systemd = Path(directory)
        resolve = systemd / "src" / "resolve"
        shared = systemd / "src" / "shared"

        write(
            resolve / "resolved-bus.c",
            '''
            SD_BUS_METHOD_WITH_ARGS("ResolveHostname", a, b, handler, 0),
            SD_BUS_PROPERTY("DNS", "a(iiay)", getter, 0, 0),
            SD_BUS_SIGNAL_WITH_ARGS("Changed", a, 0),
            ''',
        )
        write(
            resolve / "resolved-link-bus.c",
            '''
            SD_BUS_METHOD("SetDNS", "a(iay)", "", handler, 0),
            SD_BUS_PROPERTY_WITH_OFFSET("ScopesMask", "t", value, 0),
            ''',
        )
        write(
            resolve / "resolved-dnssd-bus.c",
            'SD_BUS_PROPERTY("Name", "s", getter, 0, 0);\n',
        )
        write(
            resolve / "resolved-dns-delegate-bus.c",
            'SD_BUS_METHOD_WITH_ARGS("Activate", a, b, handler, 0);\n',
        )
        write(
            shared / "varlink-io.systemd.Resolve.c",
            '''
            SD_VARLINK_DEFINE_METHOD(ResolveHostname, a, b);
            SD_VARLINK_DEFINE_ERROR(NoNameServers);
            SD_VARLINK_DEFINE_ENUM_TYPE(DNSProtocol, a);
            ''',
        )
        write(
            shared / "varlink-io.systemd.Resolve.Monitor.c",
            '''
            SD_VARLINK_DEFINE_METHOD_FULL(SubscribeQueryResults, a, b);
            SD_VARLINK_DEFINE_ERROR_TYPE(SubscriptionRefused, a);
            ''',
        )
        write(
            resolve / "resolved-gperf.gperf",
            'Resolve.DNS, config_parse_dns_servers, 0, offsetof(Manager, dns_servers)\n',
        )
        write(
            resolve / "resolvectl.c",
            '''
            VERB(verb_query, "query", "HOSTNAME", 2, VERB_ANY, 0, "query"),
            VERB(verb_statistics, "statistics", NULL, 1, 1, 0, "stats"),
            ''',
        )

        dbus = module.dbus_interfaces(systemd)
        assert [item["name"] for item in dbus["org.freedesktop.resolve1.Manager"]] == [
            "ResolveHostname",
            "DNS",
            "Changed",
        ]
        assert dbus["org.freedesktop.resolve1.Link"][0]["name"] == "SetDNS"
        assert dbus["org.freedesktop.resolve1.DnssdService"][0]["name"] == "Name"
        assert dbus["org.freedesktop.resolve1.DnsDelegate"][0]["name"] == "Activate"

        varlink = module.varlink_surfaces(systemd)
        assert varlink["methods"] == ["ResolveHostname", "SubscribeQueryResults"]
        assert varlink["errors"] == ["NoNameServers", "SubscriptionRefused"]
        assert varlink["enums"] == ["DNSProtocol"]
        assert module.configuration_keys(systemd) == ["DNS"]
        assert module.resolvectl_verbs(systemd) == ["query", "statistics"]

    print("upstream resolver surface parser tests passed")


if __name__ == "__main__":
    main()
