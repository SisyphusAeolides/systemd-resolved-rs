// SPDX-License-Identifier: LGPL-2.1-or-later

const MONITOR_INTERFACE_DESCRIPTION: &str = "interface io.systemd.Resolve.Monitor\n\
type ResourceKey (class: ?int, type: int, name: string)\n\
type ResourceRecord (key: ResourceKey, address: ?[]int, items: ?[]string)\n\
type CacheEntry (key: ResourceKey, rrs: ?[](rr: ?ResourceRecord, raw: string), type: ?string, until: int)\n\
type ScopeCache (protocol: string, family: ?int, ifindex: ?int, ifname: ?string, cache: []CacheEntry, dnssec: ?string, dnsOverTLS: ?string)\n\
method DumpCache() -> (dump: []ScopeCache)\n\
type ServerState (Server: string, Type: string, Interface: ?string, InterfaceIndex: ?int, VerifiedFeatureLevel: string, PossibleFeatureLevel: string, DNSSECMode: string, DNSSECSupported: bool, ReceivedUDPFragmentMax: int, FailedUDPAttempts: int, FailedTCPAttempts: int, PacketTruncated: bool, PacketBadOpt: bool, PacketRRSIGMissing: bool, PacketInvalid: bool, PacketDoOff: bool)\n\
method DumpServerState() -> (dump: []ServerState)\n\
type TransactionStatistics (currentTransactions: int, totalTransactions: int, totalTimeouts: int, totalTimeoutsServedStale: int, totalFailedResponses: int, totalFailedResponsesServedStale: int)\n\
type CacheStatistics (size: int, hits: int, misses: int)\n\
type DnssecStatistics (secure: int, insecure: int, bogus: int, indeterminate: int)\n\
method DumpStatistics() -> (transactions: TransactionStatistics, cache: CacheStatistics, dnssec: DnssecStatistics)\n\
method ResetStatistics()";

fn monitor_dump_cache(_can_control: bool, resolver: &Resolver) -> Value {
    let mut scopes = Vec::new();
    scopes.push(monitor_scope_cache(
        "dns",
        None,
        None,
        None,
        resolver
            .cache_snapshot()
            .into_iter()
            .map(monitor_cache_entry)
            .collect(),
        Some(validation_mode_name(resolver.config().dnssec)),
        Some(tls_mode_name(resolver.config().dns_over_tls)),
    ));
    for link in resolver.links() {
        let ifname = link.kernel.as_ref().map(|kernel| kernel.ifname.as_str());
        scopes.push(monitor_scope_cache(
            "dns",
            None,
            Some(link.ifindex),
            ifname,
            Vec::new(),
            Some(validation_mode_name(link.dnssec)),
            Some(tls_mode_name(link.dns_over_tls)),
        ));
    }
    success(Value::object([("dump", Value::Array(scopes))]))
}

fn monitor_scope_cache(
    protocol: &str,
    family: Option<i32>,
    ifindex: Option<i32>,
    ifname: Option<&str>,
    cache: Vec<Value>,
    dnssec: Option<&str>,
    dns_over_tls: Option<&str>,
) -> Value {
    let mut fields = BTreeMap::from([
        ("protocol".to_owned(), Value::String(protocol.to_owned())),
        ("cache".to_owned(), Value::Array(cache)),
    ]);
    if let Some(family) = family {
        fields.insert("family".to_owned(), Value::Number(i128::from(family)));
    }
    if let Some(ifindex) = ifindex {
        fields.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
    }
    if let Some(ifname) = ifname {
        fields.insert("ifname".to_owned(), Value::String(ifname.to_owned()));
    }
    if let Some(dnssec) = dnssec {
        fields.insert("dnssec".to_owned(), Value::String(dnssec.to_owned()));
    }
    if let Some(dns_over_tls) = dns_over_tls {
        fields.insert(
            "dnsOverTLS".to_owned(),
            Value::String(dns_over_tls.to_owned()),
        );
    }
    Value::Object(fields)
}

fn monitor_cache_entry(entry: crate::cache::CacheSnapshot) -> Value {
    let mut fields = BTreeMap::from([
        (
            "key".to_owned(),
            monitor_resource_key(&entry.name, entry.class, entry.rr_type),
        ),
        (
            "until".to_owned(),
            Value::Number(cache_until_usec(entry.remaining)),
        ),
    ]);
    let records = if entry.rcode == 0 {
        extract_answer_records(&entry.response).unwrap_or_default()
    } else {
        Vec::new()
    };
    if entry.rcode == 0 && !records.is_empty() {
        fields.insert(
            "rrs".to_owned(),
            Value::Array(
                records
                    .into_iter()
                    .map(|record| {
                        Value::object([
                            ("rr", monitor_resource_record(&record)),
                            ("raw", Value::String(base64(&record.raw))),
                        ])
                    })
                    .collect(),
            ),
        );
    } else {
        fields.insert(
            "type".to_owned(),
            Value::String(cache_type_name(entry.rcode).to_owned()),
        );
    }
    Value::Object(fields)
}

fn monitor_resource_key(name: &[u8], class: u16, rr_type: u16) -> Value {
    Value::object([
        ("class", Value::Number(i128::from(class))),
        ("type", Value::Number(i128::from(rr_type))),
        ("name", Value::String(wire_name_text(name))),
    ])
}

fn monitor_resource_record(record: &crate::wire::AnswerRecord) -> Value {
    let mut fields = BTreeMap::from([(
        "key".to_owned(),
        monitor_resource_key(
            record.name.canonical_wire(),
            record.class,
            record.rr_type,
        ),
    )]);
    if let Ok(parsed) = crate::wire::parse_record(&record.raw, 0) {
        match (record.rr_type, parsed.rdata.as_slice()) {
            (TYPE_A, [a, b, c, d]) => {
                fields.insert(
                    "address".to_owned(),
                    Value::Array(
                        [*a, *b, *c, *d]
                            .into_iter()
                            .map(|byte| Value::Number(i128::from(byte)))
                            .collect(),
                    ),
                );
            }
            (TYPE_AAAA, bytes) if bytes.len() == 16 => {
                fields.insert(
                    "address".to_owned(),
                    Value::Array(
                        bytes
                            .iter()
                            .copied()
                            .map(|byte| Value::Number(i128::from(byte)))
                            .collect(),
                    ),
                );
            }
            (TYPE_TXT, bytes) => {
                let items = monitor_txt_items(bytes);
                if !items.is_empty() {
                    fields.insert("items".to_owned(), Value::Array(items));
                }
            }
            _ => {}
        }
    }
    Value::Object(fields)
}

fn monitor_txt_items(mut bytes: &[u8]) -> Vec<Value> {
    let mut items = Vec::new();
    while let Some((&length, rest)) = bytes.split_first() {
        let length = usize::from(length);
        if rest.len() < length {
            return Vec::new();
        }
        items.push(Value::String(octescape(&rest[..length])));
        bytes = &rest[length..];
    }
    items
}

fn wire_name_text(wire: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut offset = 0usize;
    while let Some(&length) = wire.get(offset) {
        offset += 1;
        if length == 0 {
            return if labels.is_empty() {
                ".".to_owned()
            } else {
                labels.join(".")
            };
        }
        let length = usize::from(length);
        if length > 63 {
            return "<invalid>".to_owned();
        }
        let Some(label) = wire.get(offset..offset.saturating_add(length)) else {
            return "<invalid>".to_owned();
        };
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += length;
    }
    "<invalid>".to_owned()
}

fn cache_until_usec(remaining: Duration) -> i128 {
    let remaining = i128::try_from(remaining.as_micros()).unwrap_or(i128::MAX);
    boottime_usec().saturating_add(remaining)
}

fn boottime_usec() -> i128 {
    let Ok(uptime) = fs::read_to_string("/proc/uptime") else {
        return 0;
    };
    let Some(value) = uptime.split_whitespace().next() else {
        return 0;
    };
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    let Ok(seconds) = seconds.parse::<u128>() else {
        return 0;
    };
    let mut fractional_micros = 0u128;
    let mut scale = 100_000u128;
    for byte in fraction.bytes().take(6) {
        if !byte.is_ascii_digit() {
            return 0;
        }
        fractional_micros = fractional_micros
            .saturating_add(u128::from(byte - b'0').saturating_mul(scale));
        scale /= 10;
    }
    let micros = seconds
        .saturating_mul(1_000_000)
        .saturating_add(fractional_micros);
    i128::try_from(micros).unwrap_or(i128::MAX)
}

const fn cache_type_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NODATA",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        5 => "REFUSED",
        _ => "ERROR",
    }
}

fn monitor_dump_server_state(_can_control: bool, resolver: &Resolver) -> Value {
    success(Value::object([(
        "dump",
        Value::Array(
            resolver
                .server_state_snapshot()
                .into_iter()
                .map(monitor_server_state)
                .collect(),
        ),
    )]))
}

fn monitor_server_state(state: crate::resolver::ResolverServerState) -> Value {
    let mut fields = BTreeMap::from([
        ("Server".to_owned(), Value::String(state.server)),
        ("Type".to_owned(), Value::String(state.server_type)),
        (
            "VerifiedFeatureLevel".to_owned(),
            Value::String(state.verified_feature_level),
        ),
        (
            "PossibleFeatureLevel".to_owned(),
            Value::String(state.possible_feature_level),
        ),
        ("DNSSECMode".to_owned(), Value::String(state.dnssec_mode)),
        (
            "DNSSECSupported".to_owned(),
            Value::Bool(state.dnssec_supported),
        ),
        (
            "ReceivedUDPFragmentMax".to_owned(),
            Value::Number(i128::from(state.received_udp_fragment_max)),
        ),
        (
            "FailedUDPAttempts".to_owned(),
            Value::Number(i128::from(state.failed_udp_attempts)),
        ),
        (
            "FailedTCPAttempts".to_owned(),
            Value::Number(i128::from(state.failed_tcp_attempts)),
        ),
        (
            "PacketTruncated".to_owned(),
            Value::Bool(state.packet_truncated),
        ),
        ("PacketBadOpt".to_owned(), Value::Bool(state.packet_bad_opt)),
        (
            "PacketRRSIGMissing".to_owned(),
            Value::Bool(state.packet_rrsig_missing),
        ),
        ("PacketInvalid".to_owned(), Value::Bool(state.packet_invalid)),
        ("PacketDoOff".to_owned(), Value::Bool(state.packet_do_off)),
    ]);
    if let Some(interface) = state.interface {
        fields.insert("Interface".to_owned(), Value::String(interface));
    }
    if let Some(ifindex) = state.interface_index {
        fields.insert(
            "InterfaceIndex".to_owned(),
            Value::Number(i128::from(ifindex)),
        );
    }
    Value::Object(fields)
}

fn monitor_dump_statistics(_can_control: bool, resolver: &Resolver) -> Value {
    let statistics = resolver.stats();
    success(Value::object([
        (
            "transactions",
            Value::object([
                (
                    "currentTransactions",
                    Value::Number(i128::from(statistics.current_transactions)),
                ),
                (
                    "totalTransactions",
                    Value::Number(i128::from(statistics.transactions)),
                ),
                (
                    "totalTimeouts",
                    Value::Number(i128::from(statistics.timeouts)),
                ),
                (
                    "totalTimeoutsServedStale",
                    Value::Number(i128::from(statistics.timeouts_served_stale)),
                ),
                (
                    "totalFailedResponses",
                    Value::Number(i128::from(statistics.failures)),
                ),
                (
                    "totalFailedResponsesServedStale",
                    Value::Number(i128::from(statistics.failures_served_stale)),
                ),
            ]),
        ),
        (
            "cache",
            Value::object([
                (
                    "size",
                    Value::Number(i128::try_from(statistics.cache_entries).unwrap_or(i128::MAX)),
                ),
                ("hits", Value::Number(i128::from(statistics.cache_hits))),
                (
                    "misses",
                    Value::Number(i128::from(statistics.cache_misses)),
                ),
            ]),
        ),
        (
            "dnssec",
            Value::object([
                ("secure", Value::Number(0)),
                ("insecure", Value::Number(0)),
                ("bogus", Value::Number(0)),
                ("indeterminate", Value::Number(0)),
            ]),
        ),
    ]))
}

fn monitor_reset_statistics(can_control: bool, resolver: &Resolver) -> Value {
    monitor_authorized(can_control, || {
        resolver.reset_statistics();
        success(Value::Object(BTreeMap::new()))
    })
}

fn monitor_authorized(can_control: bool, operation: impl FnOnce() -> Value) -> Value {
    if !can_control {
        return error("org.varlink.service.PermissionDenied");
    }
    operation()
}

#[cfg(test)]
mod monitor_tests {
    use super::*;
    use crate::config::{Config, DnsServerSpec};

    #[test]
    fn interface_description_lists_pinned_monitor_dumps() {
        for name in [
            "DumpCache",
            "DumpServerState",
            "DumpStatistics",
            "ResetStatistics",
        ] {
            assert!(MONITOR_INTERFACE_DESCRIPTION.contains(name), "{name}");
        }
        for field in [
            "ReceivedUDPFragmentMax",
            "FailedUDPAttempts",
            "PacketRRSIGMissing",
            "totalFailedResponsesServedStale",
            "indeterminate",
        ] {
            assert!(MONITOR_INTERFACE_DESCRIPTION.contains(field), "{field}");
        }
    }

    #[test]
    fn monitor_dumps_are_readable_but_reset_requires_privilege() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"io.systemd.Resolve.Monitor.DumpStatistics","parameters":{}}"#,
            &resolver,
        );
        assert!(reply.get("error").is_none(), "{}", reply.to_json());

        let reply = dispatch(
            r#"{"method":"io.systemd.Resolve.Monitor.ResetStatistics","parameters":{}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("org.varlink.service.PermissionDenied")
        );
    }

    #[test]
    fn statistics_dump_uses_nested_upstream_contract() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch_with_access(
            r#"{"method":"io.systemd.Resolve.Monitor.DumpStatistics","parameters":{}}"#,
            &resolver,
            true,
        );
        let parameters = reply.get("parameters").expect("parameters");
        assert!(parameters.get("transactions").is_some());
        assert!(parameters.get("cache").is_some());
        assert!(parameters.get("dnssec").is_some());
        assert_eq!(
            parameters
                .get("cache")
                .and_then(|cache| cache.get("size"))
                .and_then(Value::as_u64),
            Some(0)
        );
    }

    #[test]
    fn server_state_dump_reports_configured_identity() {
        let server = DnsServerSpec {
            address: "192.0.2.53:853".parse().expect("server"),
            interface: Some("7".to_owned()),
            server_name: Some("resolver.example".to_owned()),
        };
        let resolver = Resolver::new(Config {
            upstreams: vec![server.address],
            upstream_specs: vec![server],
            ..Config::default()
        });
        let reply = dispatch_with_access(
            r#"{"method":"io.systemd.Resolve.Monitor.DumpServerState","parameters":{}}"#,
            &resolver,
            true,
        );
        let server = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("dump"))
            .and_then(Value::as_array)
            .and_then(|servers| servers.first())
            .expect("server state");
        assert_eq!(server.get("Type").and_then(Value::as_str), Some("system"));
        assert_eq!(
            server.get("Server").and_then(Value::as_str),
            Some("192.0.2.53:853%7#resolver.example")
        );
        assert_eq!(
            server.get("VerifiedFeatureLevel").and_then(Value::as_str),
            Some("n/a")
        );
        assert_eq!(
            server
                .get("ReceivedUDPFragmentMax")
                .and_then(Value::as_u64),
            Some(512)
        );
    }

    #[test]
    fn cache_dump_reports_global_scope_even_when_empty() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch_with_access(
            r#"{"method":"io.systemd.Resolve.Monitor.DumpCache","parameters":{}}"#,
            &resolver,
            true,
        );
        let scopes = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("dump"))
            .and_then(Value::as_array)
            .expect("scope dump");
        assert_eq!(
            scopes[0].get("protocol").and_then(Value::as_str),
            Some("dns")
        );
        assert_eq!(
            scopes[0]
                .get("cache")
                .and_then(Value::as_array)
                .map(|cache| cache.len()),
            Some(0)
        );
    }
}
