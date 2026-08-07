// SPDX-License-Identifier: LGPL-2.1-or-later
pub fn parse_server_spec(value: &str) -> Result<DnsServerSpec, ConfigError> {
    let original = value.trim();
    if original.is_empty() {
        return Err(ConfigError::InvalidServer(value.to_owned()));
    }

    let (address_and_interface, server_name) = match original.split_once('#') {
        Some((address, name)) if valid_server_name(name) => (address, Some(name.to_owned())),
        Some(_) => return Err(ConfigError::InvalidServer(value.to_owned())),
        None => (original, None),
    };
    let (address, interface) = match address_and_interface.split_once('%') {
        Some((address, interface)) if valid_interface(interface) => {
            (address, Some(interface.to_owned()))
        }
        Some(_) => return Err(ConfigError::InvalidServer(value.to_owned())),
        None => (address_and_interface, None),
    };
    if address.contains('#') || address.contains('%') {
        return Err(ConfigError::InvalidServer(value.to_owned()));
    }

    let address = if let Ok(address) = address.parse::<SocketAddr>() {
        address
    } else if let Ok(address) = address.parse::<IpAddr>() {
        SocketAddr::new(address, 53)
    } else {
        return Err(ConfigError::InvalidServer(value.to_owned()));
    };

    Ok(DnsServerSpec {
        address,
        interface,
        server_name,
    })
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value.chars().any(char::is_whitespace)
        && !value.contains(['%', '#'])
}

fn valid_server_name(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.is_empty()
        && value.is_ascii()
        && value.len() <= 253
        && !value.contains(['%', '#'])
        && value
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
}

#[cfg(test)]
mod server_spec_tests {
    use super::*;

    #[test]
    fn parses_address_port_interface_and_server_name() {
        let spec = parse_server_spec("1.1.1.1:853%2#one.one.one.one").expect("server spec");
        assert_eq!(spec.address, "1.1.1.1:853".parse().expect("address"));
        assert_eq!(spec.interface.as_deref(), Some("2"));
        assert_eq!(spec.server_name.as_deref(), Some("one.one.one.one"));

        let spec = parse_server_spec("[2001:db8::53]:853%eth0#resolver.example")
            .expect("IPv6 server spec");
        assert_eq!(
            spec.address,
            "[2001:db8::53]:853".parse().expect("IPv6 address")
        );
        assert_eq!(spec.interface.as_deref(), Some("eth0"));
        assert_eq!(spec.server_name.as_deref(), Some("resolver.example"));
    }

    #[test]
    fn raw_addresses_keep_default_dns_port() {
        let ipv4 = parse_server_spec("192.0.2.53").expect("IPv4 server");
        assert_eq!(ipv4.address, "192.0.2.53:53".parse().expect("IPv4 address"));

        let ipv6 = parse_server_spec("2001:db8::53%7#resolver.example")
            .expect("IPv6 server with metadata");
        assert_eq!(
            ipv6.address,
            "[2001:db8::53]:53".parse().expect("IPv6 address")
        );
        assert_eq!(ipv6.interface.as_deref(), Some("7"));
        assert_eq!(ipv6.server_name.as_deref(), Some("resolver.example"));
    }

    #[test]
    fn rejects_malformed_metadata() {
        for value in [
            "",
            "1.1.1.1%",
            "1.1.1.1#",
            "1.1.1.1%eth0%eth1",
            "1.1.1.1#resolver.example#other.example",
            "1.1.1.1%eth 0",
            "1.1.1.1#bad..name",
        ] {
            assert!(parse_server_spec(value).is_err(), "{value}");
        }
    }
}
