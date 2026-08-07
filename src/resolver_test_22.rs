#[cfg(test)]
mod test_22_logical_server_identity {
    use super::*;

    fn spec(address: SocketAddr, interface: &str, server_name: &str) -> crate::config::DnsServerSpec {
        crate::config::DnsServerSpec {
            address,
            interface: Some(interface.to_owned()),
            server_name: Some(server_name.to_owned()),
        }
    }

    #[test]
    fn same_address_metadata_expands_into_distinct_server_keys() {
        let address = "192.0.2.53:853".parse().expect("DNS server");
        let mut config = Config::default();
        config.upstreams = vec![address];
        config.upstream_specs = vec![
            spec(address, "eth0", "one.example"),
            spec(address, "eth1", "two.example"),
        ];
        config.fallback_upstreams.clear();
        config.fallback_upstream_specs.clear();
        let resolver = Resolver::new(config);

        let specs = resolver.server_specs_for_scope(ScopeKind::Global, &[address]);
        assert_eq!(specs.len(), 2);
        let keys = server_keys_for_specs(ScopeKind::Global, &specs);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].server(), address);
        assert_eq!(keys[1].server(), address);
        assert_ne!(keys[0], keys[1]);
    }

    #[test]
    fn attempted_identity_does_not_suppress_same_address_peer() {
        let address = "192.0.2.53:853".parse().expect("DNS server");
        let mut config = Config::default();
        config.upstreams = vec![address];
        config.upstream_specs = vec![
            spec(address, "eth0", "one.example"),
            spec(address, "eth1", "two.example"),
        ];
        let resolver = Resolver::new(config);
        let specs = resolver.server_specs_for_scope(ScopeKind::Global, &[address]);
        let keys = server_keys_for_specs(ScopeKind::Global, &specs);
        let mut attempted = HashSet::new();

        let first = resolver
            .select_server(&keys, &attempted)
            .expect("first identity");
        attempted.insert(first);
        let second = resolver
            .select_server(&keys, &attempted)
            .expect("second identity");

        assert_ne!(first, second);
        assert_eq!(first.server(), second.server());
    }
}
