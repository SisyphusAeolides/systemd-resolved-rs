#!/usr/bin/env python3
"""Idempotently assemble the staged mDNS/DNS-SD implementation."""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


class ReconcileError(RuntimeError):
    pass


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        raise ReconcileError(f"missing required file: {relative}")
    return path.read_text(encoding="utf-8")


def write(relative: str, content: str) -> None:
    path = ROOT / relative
    if not content.endswith("\n"):
        content += "\n"
    path.write_text(content, encoding="utf-8")


def ensure_after(content: str, anchor: str, insertion: str, description: str) -> str:
    if insertion in content:
        return content
    if anchor not in content:
        raise ReconcileError(f"cannot locate {description}")
    return content.replace(anchor, anchor + insertion, 1)


def ensure_before(content: str, anchor: str, insertion: str, description: str) -> str:
    if insertion in content:
        return content
    if anchor not in content:
        raise ReconcileError(f"cannot locate {description}")
    return content.replace(anchor, insertion + anchor, 1)


def reconcile_c() -> None:
    content = read("ffi/mdns.c")
    if "#include <limits.h>" not in content:
        content = ensure_after(
            content,
            "#include <ifaddrs.h>\n",
            "#include <limits.h>\n",
            "mDNS limits include",
        )
    content = re.sub(
        r"#ifdef SO_REUSEPORT\n.*?#endif\n",
        "",
        content,
        count=1,
        flags=re.S,
    )
    write("ffi/mdns.c", content)


def reconcile_build() -> None:
    build = read("build.rs")
    if "ffi/mdns.c" not in build:
        matches = list(
            re.finditer(r'(?m)^(?P<indent>\s*)\.file\("ffi/[^"\n]+\.c"\)', build)
        )
        if matches:
            match = matches[-1]
            build = (
                build[: match.end()]
                + f'\n{match.group("indent")}.file("ffi/mdns.c")'
                + build[match.end() :]
            )
        elif '"ffi/networkd.c"' in build:
            build = build.replace(
                '"ffi/networkd.c"', '"ffi/networkd.c",\n        "ffi/mdns.c"', 1
            )
        else:
            raise ReconcileError("cannot locate native C source list in build.rs")
    if "cargo:rerun-if-changed=ffi/mdns.c" not in build:
        build = ensure_after(
            build,
            "fn main() {\n",
            '    println!("cargo:rerun-if-changed=ffi/mdns.c");\n'
            '    println!("cargo:rerun-if-changed=ffi/mdns.h");\n',
            "build.rs main function",
        )
    write("build.rs", build)

    make = read("Makefile")
    compile_anchor = (
        "\t$(CC) $(CFLAGS) -Iffi -c ffi/networkd.c -o build/networkd.o\n"
    )
    if "ffi/mdns.c -o build/mdns.o" not in make:
        make = ensure_after(
            make,
            compile_anchor,
            "\t$(CC) $(CFLAGS) -Iffi -c ffi/mdns.c -o build/mdns.o\n"
            "\t$(CC) $(CFLAGS) -Iffi -c ffi/test_mdns.c -o build/test_mdns.o\n",
            "native compilation block",
        )
    links = [
        line
        for line in make.splitlines()
        if "build/test_native.o" in line and " -o build/test_native" in line
    ]
    if not links:
        raise ReconcileError("cannot locate native test link command")
    link = links[0]
    if "build/mdns.o" not in link:
        if " build/routing.o " in link:
            replacement = link.replace(
                " build/routing.o ", " build/mdns.o build/routing.o "
            )
        else:
            replacement = link.replace(
                " -o build/test_native", " build/mdns.o -o build/test_native"
            )
        make = make.replace(link, replacement, 1)
    if "./build/test_mdns" not in make:
        make = ensure_after(
            make,
            "\t./build/test_native\n",
            "\t$(CC) build/test_mdns.o build/mdns.o -o build/test_mdns\n"
            "\t./build/test_mdns\n",
            "native test execution",
        )
    write("Makefile", make)


def reconcile_modules() -> None:
    mdns = read("src/mdns.rs")
    for marker in (
        '#[path = "mdns_full.rs"]\npub mod parity;\n',
        '#[path = "dnssd_full.rs"]\npub mod parity_dnssd;\n',
        '#[path = "mdns_runtime.rs"]\npub mod runtime;\n',
        '#[path = "mdns_responder.rs"]\npub mod responder;\n',
        '#[path = "dnssd_config.rs"]\npub mod dnssd_config;\n',
        '#[path = "dnssd_runtime.rs"]\npub mod dnssd_runtime;\n',
    ):
        if marker not in mdns:
            if not mdns.endswith("\n"):
                mdns += "\n"
            mdns += "\n" + marker
    write("src/mdns.rs", mdns)

    resolver = read("src/resolver.rs")
    marker = 'include!("resolver_mdns_policy.rs");\n'
    if marker not in resolver:
        resolver = ensure_after(
            resolver,
            'include!("resolver_support.rs");\n',
            marker,
            "resolver support include",
        )
    write("src/resolver.rs", resolver)


POLICY = r'''impl Resolver {
    fn multicast_dns_environment_mode() -> Option<SupportMode> {
        let value = std::env::var("RESOLVED_RS_MDNS").ok()?;
        match value.trim().to_ascii_lowercase().as_str() {
            "no" | "false" | "off" | "0" => Some(SupportMode::No),
            "resolve" => Some(SupportMode::Resolve),
            "yes" | "true" | "on" | "1" => Some(SupportMode::Yes),
            _ => None,
        }
    }

    pub fn multicast_dns_mode_for_link(&self, ifindex: Option<i32>) -> SupportMode {
        if let Some(mode) = Self::multicast_dns_environment_mode() {
            return mode;
        }
        if let Some(ifindex) = ifindex {
            if let Some(link) = self.link(ifindex) {
                return link.multicast_dns;
            }
        }
        self.config().multicast_dns
    }

    pub fn multicast_dns_resolve_enabled(&self, ifindex: Option<i32>) -> bool {
        !matches!(self.multicast_dns_mode_for_link(ifindex), SupportMode::No)
    }

    pub fn multicast_dns_respond_enabled(&self, ifindex: i32) -> bool {
        matches!(
            self.multicast_dns_mode_for_link(Some(ifindex)),
            SupportMode::Yes
        )
    }
}

#[cfg(test)]
mod mdns_policy_tests {
    use super::*;

    #[test]
    fn global_mdns_policy_controls_unknown_links() {
        let mut config = Config::default();
        config.multicast_dns = SupportMode::No;
        let resolver = Resolver::new(config);
        assert!(!resolver.multicast_dns_resolve_enabled(None));
        assert!(!resolver.multicast_dns_respond_enabled(42));
    }
}
'''


def reconcile_policy_and_query() -> None:
    write("src/resolver_mdns_policy.rs", POLICY)
    query = read("src/resolver_query_on_link.rs")
    query = re.sub(
        r"// Route RFC 6762 names exclusively through the interface-scoped mDNS runtime\.\n.*?^\}\n\n",
        "",
        query,
        count=1,
        flags=re.S | re.M,
    )
    block = r'''// Route RFC 6762 names exclusively through the interface-scoped mDNS runtime.
if mode == QueryMode::Full && crate::mdns::runtime::should_handle_query(query) {
    if !self.multicast_dns_resolve_enabled(ifindex) {
        return Err(ResolveError::NoSuchResourceRecord);
    }
    let response = crate::mdns::runtime::query_raw(
        query,
        ifindex,
        self.config().query_timeout,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
    return response.ok_or(ResolveError::NoSuchResourceRecord);
}

'''
    write("src/resolver_query_on_link.rs", block + query)


def reconcile_runtime() -> None:
    runtime = read("src/mdns_runtime.rs")
    runtime = runtime.replace(
        "matches!(error.raw_os_error(), Some(13 | 19 | 98 | 99 | 101))",
        "matches!(\n"
        "                error.raw_os_error(),\n"
        "                Some(13) | Some(19) | Some(98) | Some(99) | Some(101)\n"
        "            )",
    )
    runtime = runtime.replace(
        '''            if matches!(
                error.kind(),
                io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::PermissionDenied
            ) {
                continue;
            }
''',
        '''            if matches!(
                error.raw_os_error(),
                Some(13) | Some(19) | Some(98) | Some(99) | Some(101)
            ) {
                continue;
            }
''',
    )
    runtime = runtime.replace("const DNS_FLAG_TC: u16 = 1 << 9;\n", "")
    runtime = re.sub(
        r"\n    if output\.len\(\) > usize::from\(u16::MAX\) \{\n"
        r"        output\[2\.\.4\].*?\n"
        r"        output\.truncate\(1232\);\n"
        r"    \}\n",
        "\n",
        runtime,
        count=1,
        flags=re.S,
    )
    size_check = '''    if output.len() > usize::from(u16::MAX) {
        return Err(MdnsRuntimeError::InvalidResponse(
            "translated mDNS response exceeds the DNS message limit",
        ));
    }
'''
    if "translated mDNS response exceeds the DNS message limit" not in runtime:
        anchor = "    Ok(output)\n}\n\nfn append_record("
        if anchor not in runtime:
            raise ReconcileError("cannot locate translated mDNS response completion")
        runtime = runtime.replace(anchor, size_check + anchor, 1)
    write("src/mdns_runtime.rs", runtime)


def reconcile_dnssd_config() -> None:
    config = read("src/dnssd_config.rs")
    old_load = '''    pub fn load() -> Result<Self, DnsSdConfigError> {
        let directories = DEFAULT_DIRECTORIES
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        Self::load_from_directories(&directories)
    }
'''
    new_load = '''    pub fn load() -> Result<Self, DnsSdConfigError> {
        let directories = std::env::var_os("RESOLVED_RS_DNSSD_PATH").map_or_else(
            || {
                DEFAULT_DIRECTORIES
                    .iter()
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
            },
            |value| {
                std::env::split_paths(&value)
                    .filter(|path| !path.as_os_str().is_empty())
                    .collect::<Vec<_>>()
            },
        );
        Self::load_from_directories(&directories)
    }
'''
    if "RESOLVED_RS_DNSSD_PATH" not in config:
        if old_load not in config:
            raise ReconcileError("cannot locate ServiceCatalog::load")
        config = config.replace(old_load, new_load, 1)

    config = re.sub(
        r"fn strip_comment\(value: &str\) -> &str \{.*?^\}\n",
        r'''fn strip_comment(value: &str) -> &str {
    let mut escaped = false;
    let mut quote = None;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character == '#' || character == ';' {
            return &value[..index];
        }
    }
    value
}
''',
        config,
        count=1,
        flags=re.S | re.M,
    )

    decoder = r'''fn decode_base64(
    value: &str,
    path: &Path,
    line: usize,
) -> Result<Vec<u8>, DnsSdConfigError> {
    let compact = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if compact.is_empty() {
        return Ok(Vec::new());
    }
    if compact.len() % 4 != 0 {
        return Err(parse_error(path, line, "incomplete base64 quartet"));
    }
    let mut output = Vec::with_capacity(compact.len() / 4 * 3);
    for (index, quartet) in compact.chunks_exact(4).enumerate() {
        let last = index + 1 == compact.len() / 4;
        let padding = quartet.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 || (!last && padding != 0) {
            return Err(parse_error(path, line, "invalid base64 padding"));
        }
        if quartet[..4 - padding].contains(&b'=') {
            return Err(parse_error(path, line, "base64 padding is not terminal"));
        }
        let mut values = [0u8; 4];
        for position in 0..4 - padding {
            values[position] = base64_value(quartet[position])
                .ok_or_else(|| parse_error(path, line, "invalid base64 data"))?;
        }
        if padding == 2 && values[1] & 0x0f != 0 {
            return Err(parse_error(path, line, "noncanonical base64 padding bits"));
        }
        if padding == 1 && values[2] & 0x03 != 0 {
            return Err(parse_error(path, line, "noncanonical base64 padding bits"));
        }
        output.push((values[0] << 2) | (values[1] >> 4));
        if padding < 2 {
            output.push((values[1] << 4) | (values[2] >> 2));
        }
        if padding == 0 {
            output.push((values[2] << 6) | values[3]);
        }
    }
    Ok(output)
}
'''
    config, replacements = re.subn(
        r"fn decode_base64\(.*?^\}\n\nfn base64_value",
        decoder + "\nfn base64_value",
        config,
        count=1,
        flags=re.S | re.M,
    )
    if replacements != 1:
        raise ReconcileError("cannot locate DNS-SD base64 decoder")
    write("src/dnssd_config.rs", config)

    runtime = read("src/dnssd_runtime.rs")
    runtime = runtime.replace(
        "    state.next_reload = Instant::now();\n",
        "    state.next_reload = Instant::now() + RELOAD_INTERVAL;\n",
    )
    write("src/dnssd_runtime.rs", runtime)


def responder_helpers() -> str:
    return r'''fn responder_generation(name: &NameState) -> u64 {
    name.generation ^ super::dnssd_runtime::generation().rotate_left(17)
}

fn detect_service_conflict(
    state: &InterfaceState,
    name: &NameState,
    message: &ParsedMessage,
    kind: MdnsMessageKind,
) -> bool {
    let owners = match super::dnssd_runtime::instance_owners(
        state.interface,
        &state.addresses,
        &name.label(),
    ) {
        Ok(owners) => owners,
        Err(error) => {
            eprintln!("systemd-resolved: DNS-SD conflict lookup failed: {error}");
            return false;
        }
    };
    let ours = state.records(name);
    for owner in owners.keys() {
        for rr_type in [TYPE_SRV, TYPE_TXT] {
            let our_data = ours
                .iter()
                .filter(|record| {
                    record.owner == *owner
                        && record.rr_type == rr_type
                        && record.class == CLASS_IN
                })
                .map(|record| record.rdata.clone())
                .collect::<Vec<_>>();
            if our_data.is_empty() {
                continue;
            }
            let their_data = message
                .records
                .iter()
                .filter(|record| {
                    record.owner == *owner
                        && record.rr_type == rr_type
                        && record.class == CLASS_IN
                        && (kind == MdnsMessageKind::Response
                            || record.section == ParsedSection::Authority)
                })
                .map(|record| record.rdata.clone())
                .collect::<Vec<_>>();
            if their_data.is_empty() || sets_equal(&our_data, &their_data) {
                continue;
            }
            if !state.probe.is_established()
                && kind == MdnsMessageKind::Query
                && probe_tie_break(&our_data, &their_data) != MdnsTieBreak::WeLose
            {
                continue;
            }
            match super::dnssd_runtime::rename_conflicting_owner(
                owner,
                rr_type,
                state.interface,
                &state.addresses,
                &name.label(),
            ) {
                Ok(Some(service)) => {
                    eprintln!("systemd-resolved: renamed conflicting DNS-SD service {service}");
                    return true;
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("systemd-resolved: DNS-SD conflict rename failed: {error}");
                }
            }
        }
    }
    false
}

fn add_related_records(selected: &mut BTreeSet<LocalRecord>, all_records: &[LocalRecord]) {
    loop {
        let before = selected.len();
        let current = selected.iter().cloned().collect::<Vec<_>>();
        for record in current {
            if record.rr_type == TYPE_PTR {
                for related in all_records.iter().filter(|candidate| {
                    candidate.owner == record.rdata
                        && matches!(candidate.rr_type, TYPE_SRV | TYPE_TXT)
                }) {
                    selected.insert(related.clone());
                }
            } else if record.rr_type == TYPE_SRV && record.rdata.len() >= 7 {
                let target = &record.rdata[6..];
                for related in all_records.iter().filter(|candidate| {
                    candidate.owner == target
                        && matches!(candidate.rr_type, TYPE_A | TYPE_AAAA)
                }) {
                    selected.insert(related.clone());
                }
            }
        }
        if selected.len() == before {
            break;
        }
    }
}

'''


def reconcile_responder() -> None:
    responder = read("src/mdns_responder.rs")
    if "use crate::resolver::Resolver;" not in responder:
        responder = ensure_before(
            responder,
            "use std::collections::{BTreeMap, BTreeSet, HashSet};\n",
            "use crate::resolver::Resolver;\n",
            "responder imports",
        )
    responder = re.sub(r"    resolver: Arc<Resolver>,\n", "", responder, count=1)

    old_start = re.compile(
        r"    pub fn start_from_environment\([^)]*\) -> io::Result<Option<Self>> \{.*?^    \}\n",
        re.S | re.M,
    )
    new_start = r'''    pub fn start_from_environment(
        resolver: Arc<Resolver>,
    ) -> io::Result<Option<Self>> {
        if !responder_enabled() {
            return Ok(None);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_resolver = Arc::clone(&resolver);
        let thread = thread::Builder::new()
            .name("resolved-mdns-responder".to_owned())
            .spawn(move || responder_loop(&thread_stop, &thread_resolver))?;
        Ok(Some(Self {
            stop,
            thread: Some(thread),
        }))
    }
'''
    responder, replacements = old_start.subn(new_start, responder, count=1)
    if replacements != 1:
        raise ReconcileError("cannot normalize mDNS responder constructor")
    responder = responder.replace(
        "fn responder_loop(stop: &AtomicBool) {\n",
        "fn responder_loop(stop: &AtomicBool, resolver: &Resolver) {\n",
    )
    responder = responder.replace(
        "            synchronize_interfaces(&mut interfaces, &name, now);\n",
        "            synchronize_interfaces(&mut interfaces, &name, resolver, now);\n",
    )
    responder = responder.replace(
        '''fn synchronize_interfaces(
    states: &mut BTreeMap<MdnsInterface, InterfaceState>,
    name: &NameState,
    now: Instant,
) {''',
        '''fn synchronize_interfaces(
    states: &mut BTreeMap<MdnsInterface, InterfaceState>,
    name: &NameState,
    resolver: &Resolver,
    now: Instant,
) {''',
    )
    responder = responder.replace(
        "    let discovered = match discover_interfaces() {\n",
        "    let mut discovered = match discover_interfaces() {\n",
        1,
    )
    if "multicast_dns_respond_enabled" not in responder:
        anchor = "    };\n    states.retain(|key, state| {\n"
        insertion = '''    };
    discovered.retain(|interface, _| {
        i32::try_from(interface.ifindex)
            .ok()
            .is_some_and(|ifindex| resolver.multicast_dns_respond_enabled(ifindex))
    });
    states.retain(|key, state| {
'''
        if anchor not in responder:
            raise ReconcileError("cannot locate responder interface filtering")
        responder = responder.replace(anchor, insertion, 1)

    responder = responder.replace(
        "            if state.generation != name.generation {\n",
        "            if state.generation != responder_generation(&name) {\n",
    )
    responder = responder.replace(
        "        self.generation = name.generation;\n",
        "        self.generation = responder_generation(name);\n",
    )
    responder = responder.replace(
        "                        generation: name.generation,\n",
        "                        generation: responder_generation(name),\n",
    )

    if "detect_service_conflict(state, &name" not in responder:
        anchor = (
            "                if detect_conflict(state, &name, &parsed, "
            "validated.kind, now) {\n"
        )
        insertion = '''                if detect_service_conflict(state, &name, &parsed, validated.kind) {
                    state.restart_probe(&name, now);
                    continue;
                }
'''
        responder = ensure_before(
            responder, anchor, insertion, "responder conflict dispatch"
        )

    if "DNS-SD record generation failed" not in responder:
        anchor = "    output.sort();\n    output\n}\n\nfn reverse_owner"
        replacement = '''    match super::dnssd_runtime::records_for(
        interface,
        addresses,
        &name.label(),
        false,
    ) {
        Ok(records) => output.extend(records.into_iter().map(|record| LocalRecord {
            owner: record.owner,
            rr_type: record.rr_type,
            class: record.class,
            ttl: record.ttl,
            cache_flush: record.cache_flush,
            rdata: record.rdata,
        })),
        Err(error) => eprintln!("systemd-resolved: DNS-SD record generation failed: {error}"),
    }
    output.sort();
    output.dedup();
    output
}

fn reverse_owner'''
        if anchor not in responder:
            raise ReconcileError("cannot locate responder local record completion")
        responder = responder.replace(anchor, replacement, 1)

    if "add_related_records(&mut multicast" not in responder:
        responder = ensure_before(
            responder,
            "    if !unicast.is_empty() {\n",
            "    add_related_records(&mut multicast, &all_records);\n"
            "    add_related_records(&mut unicast, &all_records);\n\n",
            "responder answer emission",
        )

    if "fn responder_generation(name: &NameState)" not in responder:
        responder = ensure_before(
            responder,
            "fn response_packet(\n",
            responder_helpers(),
            "responder response encoder",
        )

    old_probe = re.compile(
        r"fn send_probe\(state: &InterfaceState, name: &NameState\) -> io::Result<\(\)> \{.*?^\}\n",
        re.S | re.M,
    )
    new_probe = r'''fn send_probe(state: &InterfaceState, name: &NameState) -> io::Result<()> {
    let records = state.unique_records(name);
    if records.is_empty() {
        return Ok(());
    }
    let owners = records
        .iter()
        .map(|record| record.owner.clone())
        .collect::<BTreeSet<_>>();
    let question_count = u16::try_from(owners.len())
        .map_err(|_| invalid_data("too many mDNS probe owners"))?;
    let authority_count = u16::try_from(records.len())
        .map_err(|_| invalid_data("too many mDNS probe records"))?;
    let mut output = dns_header(0, 0, question_count, 0, authority_count, 0);
    for owner in owners {
        output.extend_from_slice(&owner);
        output.extend_from_slice(&TYPE_ANY.to_be_bytes());
        output.extend_from_slice(&CLASS_IN.to_be_bytes());
    }
    for record in &records {
        append_record(&mut output, record, false, None)?;
    }
    send_multicast(state, &output)
}
'''
    responder, replacements = old_probe.subn(new_probe, responder, count=1)
    if replacements != 1:
        raise ReconcileError("cannot normalize mDNS probe sender")
    write("src/mdns_responder.rs", responder)


def reconcile_daemon_and_tests() -> None:
    daemon = read("src/daemon.rs")
    function = "pub fn run_stub(resolver: &Arc<Resolver>) -> io::Result<()> {\n"
    constructor = (
        "    let mdns_responder = "
        "crate::mdns::responder::MdnsResponder::start_from_environment("
        "Arc::clone(resolver))?;\n"
    )
    if "MdnsResponder::start_from_environment" not in daemon:
        daemon = ensure_after(
            daemon, function, constructor, "daemon stub runner"
        )
    else:
        daemon = re.sub(
            r"    let mdns_responder = .*?MdnsResponder::start_from_environment\(.*?\)\?;\n",
            constructor,
            daemon,
            count=1,
            flags=re.S,
        )
    if "drop(mdns_responder);" not in daemon:
        daemon = ensure_before(
            daemon,
            "    drop(dispatcher);\n",
            "    drop(mdns_responder);\n",
            "daemon dispatcher shutdown",
        )
    reload_anchor = '''            if let Err(error) = resolver.reload_hosts() {
                eprintln!("systemd-resolved: failed to reload hosts database: {error}");
            }
'''
    if "failed to reload DNS-SD services" not in daemon:
        daemon = ensure_after(
            daemon,
            reload_anchor,
            '''            if let Err(error) = crate::mdns::dnssd_runtime::force_reload() {
                eprintln!("systemd-resolved: failed to reload DNS-SD services: {error}");
            }
''',
            "daemon reload block",
        )
    write("src/daemon.rs", daemon)

    preflight = read("scripts/preflight-replacement.sh")
    responder_line = '    "RESOLVED_RS_MDNS_RESPONDER=no" \\\n'
    if responder_line not in preflight:
        preflight = ensure_after(
            preflight,
            '    "RESOLVED_RS_RUN_DIR=$RUN_DIR" \\\n',
            responder_line,
            "preflight candidate environment",
        )
    write("scripts/preflight-replacement.sh", preflight)

    live = read("tests/live-mdns.py")
    responder_entry = '                    "RESOLVED_RS_MDNS_RESPONDER": "no",\n'
    if responder_entry not in live:
        live = ensure_after(
            live,
            '                    "RESOLVED_RS_MDNS": "yes",\n',
            responder_entry,
            "live mDNS environment",
        )
    write("tests/live-mdns.py", live)


TEMPORARY_WORKFLOWS = (
    "pin-upstream-resolved.yml",
    "land-mdns-core.yml",
    "land-dnssd-core.yml",
    "land-mdns-native.yml",
    "integrate-mdns-stack.yml",
    "finalize-mdns-integration.yml",
    "finalize-mdns-responder.yml",
    "finalize-dnssd-responder.yml",
    "finalize-dnssd-live.yml",
    "finalize-mdns-policy.yml",
    "reconcile-mdns-dnssd.yml",
)


def remove_temporary_workflows() -> None:
    directory = ROOT / ".github" / "workflows"
    for name in TEMPORARY_WORKFLOWS:
        path = directory / name
        if path.exists():
            path.unlink()


def main() -> int:
    reconcile_c()
    reconcile_build()
    reconcile_modules()
    reconcile_policy_and_query()
    reconcile_runtime()
    reconcile_dnssd_config()
    reconcile_responder()
    reconcile_daemon_and_tests()
    remove_temporary_workflows()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReconcileError) as error:
        print(f"reconcile-mdns-dnssd: {error}", file=sys.stderr)
        raise SystemExit(1) from error
