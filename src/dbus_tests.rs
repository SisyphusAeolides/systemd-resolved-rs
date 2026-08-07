// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_paths_match_systemd_bus_label_encoding() {
        assert_eq!(
            link_object_path(2).expect("path").as_str(),
            "/org/freedesktop/resolve1/link/_32"
        );
        assert_eq!(
            link_object_path(12).expect("path").as_str(),
            "/org/freedesktop/resolve1/link/_312"
        );
    }

    #[test]
    fn address_conversion_is_strict() {
        assert_eq!(
            decode_address(AF_INET, &[192, 0, 2, 1]).expect("IPv4"),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert!(decode_address(AF_INET6, &[0; 15]).is_err());
        assert!(decode_address(AF_UNSPEC, &[]).is_err());
    }

    #[test]
    fn modes_round_trip() {
        assert_eq!(
            parse_support_mode("resolve").expect("support"),
            SupportMode::Resolve
        );
        assert_eq!(
            parse_tls_mode("opportunistic").expect("TLS"),
            TlsMode::Opportunistic
        );
        assert_eq!(
            parse_validation_mode("allow-downgrade").expect("DNSSEC"),
            ValidationMode::AllowDowngrade
        );
    }

    #[test]
    fn service_names_are_validated() {
        assert!(service_owner("printer", "_ipp._tcp", "example.test").is_ok());
        assert!(service_owner("bad.name", "_ipp._tcp", "example.test").is_err());
        assert!(service_owner("printer", "ipp.tcp", "example.test").is_err());
    }

    #[test]
    fn cname_loops_keep_the_dbus_error_contract() {
        let error = map_resolve_error(ResolveError::Wire(crate::wire::WireError::CnameLoop));
        assert!(matches!(error, DbusError::CNameLoop(_)));
    }

    #[test]
    fn managed_links_keep_the_dbus_link_busy_contract() {
        let error = map_link_error(LinkError::ManagedLink(7));
        assert!(matches!(error, DbusError::LinkBusy(_)));
    }

    #[test]
    fn dns_ex_default_ports_and_server_names_round_trip() {
        let decoded = decode_dns_server_specs(vec![(
            AF_INET,
            vec![192, 0, 2, 53],
            853,
            "resolver.example".to_owned(),
        )])
        .expect("DNSEx server");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].address.port(), DNS_PORT);
        assert_eq!(decoded[0].server_name.as_deref(), Some("resolver.example"));

        let entry = link_dns_ex_entry(decoded[0].clone());
        assert_eq!(entry.2, 0);
        assert_eq!(entry.3, "resolver.example");
    }

    #[test]
    fn dns_ex_custom_ports_are_preserved() {
        assert_eq!(dns_ex_input_port(9953), 9953);
        assert_eq!(dns_ex_output_port(9953), 9953);
        assert_eq!(dns_ex_input_port(53), DNS_PORT);
        assert_eq!(dns_ex_input_port(853), DNS_PORT);
        assert_eq!(dns_ex_output_port(53), 0);
        assert_eq!(dns_ex_output_port(853), 0);
    }
}
