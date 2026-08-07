// SPDX-License-Identifier: LGPL-2.1-or-later
impl Resolver {
    fn server_spec_for_key(&self, server: ServerKey) -> DnsServerSpec {
        let specs = self.server_specs_for_scope(server.scope_kind(), &[server.server()]);
        specs
            .into_iter()
            .filter(|spec| spec.address == server.server())
            .nth(server.slot())
            .unwrap_or(DnsServerSpec {
                address: server.server(),
                interface: None,
                server_name: None,
            })
    }

    fn server_transport_ifindex(&self, server: ServerKey) -> Result<Option<i32>, ResolveError> {
        let spec = self.server_spec_for_key(server);
        match spec.interface.as_deref() {
            Some(interface) => Ok(Some(crate::interface::resolve_ifindex(interface)?)),
            None => Ok(server.ifindex()),
        }
    }
}

#[cfg(test)]
mod server_identity_tests {
    use super::*;

    #[test]
    fn global_numeric_interface_becomes_transport_ifindex() {
        let address = "192.0.2.53:53".parse().expect("DNS server");
        let config = Config {
            upstreams: vec![address],
            upstream_specs: vec![DnsServerSpec {
                address,
                interface: Some("7".to_owned()),
                server_name: Some("resolver.example".to_owned()),
            }],
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        let key = ServerKey::new(ScopeKind::Global, address);

        assert_eq!(resolver.server_transport_ifindex(key).expect("ifindex"), Some(7));
        assert_eq!(
            resolver.server_spec_for_key(key).server_name.as_deref(),
            Some("resolver.example")
        );
    }

    #[test]
    fn global_named_interface_becomes_transport_ifindex() {
        let address = "192.0.2.53:53".parse().expect("DNS server");
        let config = Config {
            upstreams: vec![address],
            upstream_specs: vec![DnsServerSpec {
                address,
                interface: Some("lo".to_owned()),
                server_name: None,
            }],
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        let key = ServerKey::new(ScopeKind::Global, address);

        assert!(resolver
            .server_transport_ifindex(key)
            .expect("loopback ifindex")
            .is_some_and(|ifindex| ifindex > 0));
    }

    #[test]
    fn link_scope_remains_default_transport_interface() {
        let address = "192.0.2.53:53".parse().expect("DNS server");
        let resolver = Resolver::new(Config::default());
        let key = ServerKey::new(ScopeKind::Link(9), address);

        assert_eq!(resolver.server_transport_ifindex(key).expect("ifindex"), Some(9));
    }
}
