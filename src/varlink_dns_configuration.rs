// SPDX-License-Identifier: LGPL-2.1-or-later

fn dump_dns_configuration(resolver: &Resolver) -> Value {
    let mut configuration = Vec::new();
    configuration.push(global_dns_configuration(resolver.config()));
    configuration.extend(
        resolver
            .links()
            .into_iter()
            .map(|link| link_dns_configuration(resolver, &link)),
    );
    success(Value::object([(
        "configuration",
        Value::Array(configuration),
    )]))
}

fn global_dns_configuration(config: &crate::config::Config) -> Value {
    let servers = configured_server_specs(config, false);
    let fallback_servers = configured_server_specs(config, true);
    let current_server = servers
        .first()
        .or_else(|| fallback_servers.first())
        .map_or(Value::Null, |server| {
            dns_server_configuration(server, None, Some(true))
        });
    let resolv_conf_mode = crate::resolvconf_publish::system_resolv_conf_mode(
        &config.runtime_directory,
    )
    .unwrap_or(crate::resolvconf_publish::ResolvConfMode::Foreign)
    .as_str()
    .to_owned();

    Value::object([
        ("ifname", Value::Null),
        ("ifindex", Value::Null),
        ("delegate", Value::Null),
        ("defaultRoute", Value::Null),
        ("currentServer", current_server),
        (
            "servers",
            Value::Array(
                servers
                    .iter()
                    .map(|server| dns_server_configuration(server, None, Some(true)))
                    .collect(),
            ),
        ),
        (
            "fallbackServers",
            Value::Array(
                fallback_servers
                    .iter()
                    .map(|server| dns_server_configuration(server, None, Some(true)))
                    .collect(),
            ),
        ),
        (
            "searchDomains",
            Value::Array(
                config
                    .domains
                    .iter()
                    .map(|domain| search_domain_configuration(domain, None))
                    .collect(),
            ),
        ),
        ("negativeTrustAnchors", Value::Null),
        (
            "dnssec",
            Value::String(validation_mode_name(config.dnssec).to_owned()),
        ),
        ("dnssecSupported", Value::Null),
        (
            "dnsOverTLS",
            Value::String(tls_mode_name(config.dns_over_tls).to_owned()),
        ),
        (
            "llmnr",
            Value::String(support_mode_name(config.llmnr).to_owned()),
        ),
        (
            "mDNS",
            Value::String(support_mode_name(config.multicast_dns).to_owned()),
        ),
        ("resolvConfMode", Value::String(resolv_conf_mode)),
        ("scopes", Value::Null),
    ])
}

fn link_dns_configuration(
    resolver: &Resolver,
    link: &crate::routing::LinkState,
) -> Value {
    let servers = resolver.link_dns_specs(link.ifindex);
    let accessible = link.kernel_relevant_unicast();
    let current_server = servers.first().map_or(Value::Null, |server| {
        dns_server_configuration(server, Some(link.ifindex), Some(accessible))
    });
    let ifname = link.kernel.as_ref().map_or(Value::Null, |kernel| {
        Value::String(kernel.ifname.clone())
    });
    let default_route = link
        .default_route
        .map_or(Value::Null, Value::Bool);

    Value::object([
        ("ifname", ifname),
        ("ifindex", Value::Number(i128::from(link.ifindex))),
        ("delegate", Value::Null),
        ("defaultRoute", default_route),
        ("currentServer", current_server),
        (
            "servers",
            Value::Array(
                servers
                    .iter()
                    .map(|server| {
                        dns_server_configuration(
                            server,
                            Some(link.ifindex),
                            Some(accessible),
                        )
                    })
                    .collect(),
            ),
        ),
        ("fallbackServers", Value::Null),
        (
            "searchDomains",
            Value::Array(
                link.domains
                    .iter()
                    .map(|domain| {
                        search_domain_configuration(domain, Some(link.ifindex))
                    })
                    .collect(),
            ),
        ),
        (
            "negativeTrustAnchors",
            Value::Array(
                link.dnssec_negative_trust_anchors
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        ),
        (
            "dnssec",
            Value::String(validation_mode_name(link.dnssec).to_owned()),
        ),
        ("dnssecSupported", Value::Null),
        (
            "dnsOverTLS",
            Value::String(tls_mode_name(link.dns_over_tls).to_owned()),
        ),
        (
            "llmnr",
            Value::String(support_mode_name(link.llmnr).to_owned()),
        ),
        (
            "mDNS",
            Value::String(support_mode_name(link.multicast_dns).to_owned()),
        ),
        ("resolvConfMode", Value::Null),
        ("scopes", Value::Null),
    ])
}

fn configured_server_specs(
    config: &crate::config::Config,
    fallback: bool,
) -> Vec<crate::config::DnsServerSpec> {
    let (specs, addresses) = if fallback {
        (&config.fallback_upstream_specs, &config.fallback_upstreams)
    } else {
        (&config.upstream_specs, &config.upstreams)
    };
    if specs.is_empty() {
        addresses
            .iter()
            .copied()
            .map(|address| crate::config::DnsServerSpec {
                address,
                interface: None,
                server_name: None,
            })
            .collect()
    } else {
        specs.clone()
    }
}

fn dns_server_configuration(
    server: &crate::config::DnsServerSpec,
    default_ifindex: Option<i32>,
    accessible: Option<bool>,
) -> Value {
    let (family, address): (i32, Vec<u8>) = match server.address.ip() {
        IpAddr::V4(address) => (2, address.octets().to_vec()),
        IpAddr::V6(address) => (10, address.octets().to_vec()),
    };
    let ifindex = server
        .interface
        .as_deref()
        .and_then(|interface| crate::interface::resolve_ifindex(interface).ok())
        .or(default_ifindex);
    let address_string = match (server.address.ip(), server.interface.as_deref()) {
        (IpAddr::V6(address), Some(interface)) => format!("{address}%{interface}"),
        (address, _) => address.to_string(),
    };

    Value::object([
        (
            "address",
            Value::Array(
                address
                    .into_iter()
                    .map(|byte| Value::Number(i128::from(byte)))
                    .collect(),
            ),
        ),
        ("addressString", Value::String(address_string)),
        ("family", Value::Number(i128::from(family))),
        (
            "port",
            Value::Number(i128::from(server.address.port())),
        ),
        (
            "ifindex",
            ifindex.map_or(Value::Null, |value| Value::Number(i128::from(value))),
        ),
        (
            "name",
            server
                .server_name
                .as_ref()
                .map_or(Value::Null, |name| Value::String(name.clone())),
        ),
        (
            "accessible",
            accessible.map_or(Value::Null, Value::Bool),
        ),
    ])
}

fn search_domain_configuration(
    domain: &crate::config::Domain,
    ifindex: Option<i32>,
) -> Value {
    Value::object([
        ("name", Value::String(domain.name.clone())),
        ("routeOnly", Value::Bool(domain.route_only)),
        (
            "ifindex",
            ifindex.map_or(Value::Null, |value| Value::Number(i128::from(value))),
        ),
    ])
}

const fn support_mode_name(mode: crate::config::SupportMode) -> &'static str {
    match mode {
        crate::config::SupportMode::No => "no",
        crate::config::SupportMode::Resolve => "resolve",
        crate::config::SupportMode::Yes => "yes",
    }
}

const fn validation_mode_name(mode: crate::config::ValidationMode) -> &'static str {
    match mode {
        crate::config::ValidationMode::No => "no",
        crate::config::ValidationMode::AllowDowngrade => "allow-downgrade",
        crate::config::ValidationMode::Yes => "yes",
    }
}

const fn tls_mode_name(mode: crate::config::TlsMode) -> &'static str {
    match mode {
        crate::config::TlsMode::No => "no",
        crate::config::TlsMode::Opportunistic => "opportunistic",
        crate::config::TlsMode::Yes => "yes",
    }
}

#[cfg(test)]
mod dns_configuration_tests {
    use super::*;
    use crate::config::{
        Config, DnsServerSpec, Domain, SupportMode, TlsMode, ValidationMode,
    };
    use crate::routing::KernelLinkState;

    #[test]
    fn dump_reports_global_and_per_link_configuration() {
        let global_server = DnsServerSpec {
            address: "192.0.2.53:9953".parse().expect("global server"),
            interface: None,
            server_name: Some("resolver.example".to_owned()),
        };
        let fallback_server = DnsServerSpec {
            address: "198.51.100.53:53".parse().expect("fallback server"),
            interface: None,
            server_name: None,
        };
        let config = Config {
            upstreams: vec![global_server.address],
            upstream_specs: vec![global_server],
            fallback_upstreams: vec![fallback_server.address],
            fallback_upstream_specs: vec![fallback_server],
            domains: vec![Domain {
                name: "example.test".to_owned(),
                route_only: false,
            }],
            dnssec: ValidationMode::Yes,
            dns_over_tls: TlsMode::Opportunistic,
            llmnr: SupportMode::Resolve,
            multicast_dns: SupportMode::Yes,
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        resolver
            .sync_kernel_links(vec![KernelLinkState {
                ifindex: 7,
                ifname: "test7".to_owned(),
                flags: 0x1_0001,
                mtu: 1500,
                operstate: 6,
                has_ipv4_global: true,
                has_ipv4_link_local: false,
                has_ipv6_global: false,
                has_ipv6_link_local: false,
            }])
            .expect("synchronize link");
        resolver
            .set_link_dns_specs(
                7,
                vec![DnsServerSpec {
                    address: "203.0.113.53:853".parse().expect("link server"),
                    interface: Some("test7".to_owned()),
                    server_name: Some("link-resolver.example".to_owned()),
                }],
            )
            .expect("set link DNS");
        resolver
            .set_link_domains(
                7,
                vec![Domain {
                    name: "corp.example".to_owned(),
                    route_only: true,
                }],
            )
            .expect("set link domains");
        resolver
            .set_link_default_route(7, Some(true))
            .expect("set link default route");
        resolver
            .set_link_dnssec_negative_trust_anchors(
                7,
                vec!["internal.example".to_owned()],
            )
            .expect("set link NTA");

        let reply = dispatch(
            r#"{"method":"io.systemd.Resolve.DumpDNSConfiguration","parameters":{}}"#,
            &resolver,
        );
        assert!(reply.get("error").is_none(), "{}", reply.to_json());
        let configuration = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("configuration"))
            .and_then(Value::as_array)
            .expect("configuration array");
        assert_eq!(configuration.len(), 2);

        let global = &configuration[0];
        let current = global.get("currentServer").expect("current global server");
        assert_eq!(current.get("port").and_then(Value::as_u64), Some(9953));
        assert_eq!(
            current.get("name").and_then(Value::as_str),
            Some("resolver.example")
        );
        assert_eq!(global.get("dnssec").and_then(Value::as_str), Some("yes"));
        assert!(global.get("resolvConfMode").and_then(Value::as_str).is_some());

        let link = &configuration[1];
        assert_eq!(link.get("ifindex").and_then(Value::as_i64), Some(7));
        assert_eq!(link.get("ifname").and_then(Value::as_str), Some("test7"));
        assert_eq!(link.get("defaultRoute").and_then(Value::as_bool), Some(true));
        let link_server = link
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|servers| servers.first())
            .expect("link server");
        assert_eq!(link_server.get("port").and_then(Value::as_u64), Some(853));
        assert_eq!(
            link_server.get("name").and_then(Value::as_str),
            Some("link-resolver.example")
        );
        assert_eq!(
            link_server.get("accessible").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            link.get("searchDomains")
                .and_then(Value::as_array)
                .and_then(|domains| domains.first())
                .and_then(|domain| domain.get("routeOnly"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            link.get("negativeTrustAnchors")
                .and_then(Value::as_array)
                .and_then(|anchors| anchors.first())
                .and_then(Value::as_str),
            Some("internal.example")
        );
    }
}
