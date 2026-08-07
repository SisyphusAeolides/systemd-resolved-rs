#[cfg(test)]
mod test_21_networkd_link_state {
    use super::*;
    use crate::networkd::OperationalState;
    use crate::routing::KernelLinkState;

    fn kernel_link(ifindex: i32) -> KernelLinkState {
        KernelLinkState {
            ifindex,
            ifname: format!("test{ifindex}"),
            flags: 0x0001 | 0x0040 | 0x1_0000,
            mtu: 1500,
            operstate: 0,
            has_ipv4_global: true,
            has_ipv4_link_local: false,
            has_ipv6_global: false,
            has_ipv6_link_local: false,
        }
    }

    fn networkd_link(ifindex: i32, operstate: OperationalState) -> NetworkdLinkState {
        let address = "192.0.2.53:53".parse().expect("DNS server");
        NetworkdLinkState {
            ifindex,
            managed: true,
            operstate,
            dns_servers: vec![address],
            dns_server_specs: vec![DnsServerSpec {
                address,
                interface: Some(format!("test{ifindex}")),
                server_name: Some("resolver.example".to_owned()),
            }],
            domains: vec![Domain {
                name: "corp.example".to_owned(),
                route_only: true,
            }],
            default_route: Some(false),
            llmnr: SupportMode::Resolve,
            multicast_dns: SupportMode::No,
            dns_over_tls: Some(TlsMode::Opportunistic),
            dnssec: Some(ValidationMode::No),
            dnssec_negative_trust_anchors: vec!["private.example".to_owned()],
        }
    }

    #[test]
    fn managed_networkd_state_populates_effective_link_and_blocks_mutation() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link state");
        resolver
            .sync_networkd_links(vec![networkd_link(7, OperationalState::Routable)])
            .expect("networkd link state");

        let link = resolver.link(7).expect("link state");
        assert_eq!(link.dns_servers.len(), 1);
        assert_eq!(link.domains.len(), 1);
        assert_eq!(link.default_route, Some(false));
        assert_eq!(link.llmnr, SupportMode::Resolve);
        assert_eq!(link.multicast_dns, SupportMode::No);
        assert_eq!(link.dns_over_tls, TlsMode::Opportunistic);
        assert_eq!(link.dnssec, ValidationMode::No);
        assert_eq!(
            link.dnssec_negative_trust_anchors,
            vec!["private.example".to_owned()]
        );
        let specs = resolver.link_dns_specs(7);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].interface.as_deref(), Some("test7"));
        assert_eq!(specs[0].server_name.as_deref(), Some("resolver.example"));
        assert!(resolver.link_is_managed(7));
        assert_eq!(
            resolver.set_link_dns(7, vec!["198.51.100.53:53".parse().expect("DNS server")]),
            Err(LinkError::ManagedLink(7))
        );
    }

    #[test]
    fn networkd_operstate_controls_link_scope_relevance() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link state");
        resolver
            .sync_networkd_links(vec![networkd_link(7, OperationalState::Carrier)])
            .expect("carrier state");
        assert!(!resolver.networkd_link_relevant(7));

        resolver
            .sync_networkd_links(vec![networkd_link(7, OperationalState::Routable)])
            .expect("routable state");
        assert!(resolver.networkd_link_relevant(7));
    }

    #[test]
    fn managed_to_unmanaged_transition_reverts_resolver_state_only() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link state");
        resolver
            .sync_networkd_links(vec![networkd_link(7, OperationalState::Routable)])
            .expect("managed state");

        let mut unmanaged = networkd_link(7, OperationalState::Routable);
        unmanaged.managed = false;
        unmanaged.dns_servers.clear();
        unmanaged.dns_server_specs.clear();
        unmanaged.domains.clear();
        resolver
            .sync_networkd_links(vec![unmanaged])
            .expect("unmanaged state");

        let link = resolver.link(7).expect("kernel link survives");
        assert!(!resolver.link_is_managed(7));
        assert!(link.dns_servers.is_empty());
        assert!(resolver.link_dns_specs(7).is_empty());
        assert!(link.domains.is_empty());
        assert!(link.kernel.is_some());
    }
}
