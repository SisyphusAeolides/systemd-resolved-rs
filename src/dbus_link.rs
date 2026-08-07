// SPDX-License-Identifier: LGPL-2.1-or-later
#[derive(Debug)]
struct LinkObject {
    resolver: Arc<Resolver>,
    ifindex: i32,
}

#[dbus_interface(name = "org.freedesktop.resolve1.Link")]
impl LinkObject {
    #[dbus_interface(name = "SetDNS")]
    fn set_dns(&self, addresses: Vec<(i32, Vec<u8>)>) -> Result<(), DbusError> {
        self.resolver
            .set_link_dns(self.ifindex, decode_dns_servers(addresses, DNS_PORT)?)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetDNSEx")]
    fn set_dns_ex(&self, addresses: Vec<(i32, Vec<u8>, u16, String)>) -> Result<(), DbusError> {
        self.resolver
            .set_link_dns_specs(self.ifindex, decode_dns_server_specs(addresses)?)
            .map_err(map_link_error)
    }

    fn set_domains(&self, domains: Vec<(String, bool)>) -> Result<(), DbusError> {
        self.resolver
            .set_link_domains(
                self.ifindex,
                domains
                    .into_iter()
                    .map(|(name, route_only)| Domain { name, route_only })
                    .collect(),
            )
            .map_err(map_link_error)
    }

    fn set_default_route(&self, enable: bool) -> Result<(), DbusError> {
        self.resolver
            .set_link_default_route(self.ifindex, Some(enable))
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetLLMNR")]
    fn set_llmnr(&self, mode: &str) -> Result<(), DbusError> {
        self.resolver
            .set_link_llmnr(self.ifindex, parse_support_mode(mode)?)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetMulticastDNS")]
    fn set_multicast_dns(&self, mode: &str) -> Result<(), DbusError> {
        self.resolver
            .set_link_multicast_dns(self.ifindex, parse_support_mode(mode)?)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetDNSOverTLS")]
    fn set_dns_over_tls(&self, mode: &str) -> Result<(), DbusError> {
        self.resolver
            .set_link_dns_over_tls(self.ifindex, parse_tls_mode(mode)?)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetDNSSEC")]
    fn set_dnssec(&self, mode: &str) -> Result<(), DbusError> {
        self.resolver
            .set_link_dnssec(self.ifindex, parse_validation_mode(mode)?)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetDNSSECNegativeTrustAnchors")]
    fn set_dnssec_negative_trust_anchors(&self, names: Vec<String>) -> Result<(), DbusError> {
        self.resolver
            .set_link_dnssec_negative_trust_anchors(self.ifindex, names)
            .map_err(map_link_error)
    }

    fn revert(&self) -> Result<(), DbusError> {
        self.resolver
            .revert_link(self.ifindex)
            .map_err(map_link_error)
    }

    #[dbus_interface(property, name = "ScopesMask")]
    fn scopes_mask(&self) -> Result<u64, zbus::fdo::Error> {
        let link = self.state()?;
        let mut mask = if link.dns_servers.is_empty() {
            0
        } else {
            SD_RESOLVED_DNS
        };
        if link.llmnr != SupportMode::No {
            mask |= SD_RESOLVED_LLMNR_IPV4 | SD_RESOLVED_LLMNR_IPV6;
        }
        if link.multicast_dns != SupportMode::No {
            mask |= SD_RESOLVED_MDNS_IPV4 | SD_RESOLVED_MDNS_IPV6;
        }
        Ok(mask)
    }

    #[dbus_interface(property, name = "DNS")]
    fn dns(&self) -> Result<Vec<(i32, Vec<u8>)>, zbus::fdo::Error> {
        Ok(self
            .state()?
            .dns_servers
            .into_iter()
            .map(link_dns_entry)
            .collect())
    }

    #[dbus_interface(property, name = "DNSEx")]
    fn dns_ex(&self) -> Vec<(i32, Vec<u8>, u16, String)> {
        self.resolver
            .link_dns_specs(self.ifindex)
            .into_iter()
            .map(link_dns_ex_entry)
            .collect()
    }

    #[dbus_interface(property, name = "CurrentDNSServer")]
    fn current_dns_server(&self) -> Result<(i32, Vec<u8>), zbus::fdo::Error> {
        Ok(self
            .state()?
            .dns_servers
            .first()
            .copied()
            .map_or((AF_UNSPEC, Vec::new()), link_dns_entry))
    }

    #[dbus_interface(property, name = "CurrentDNSServerEx")]
    fn current_dns_server_ex(&self) -> (i32, Vec<u8>, u16, String) {
        self.resolver
            .link_dns_specs(self.ifindex)
            .into_iter()
            .next()
            .map_or((AF_UNSPEC, Vec::new(), 0, String::new()), link_dns_ex_entry)
    }

    #[dbus_interface(property, name = "Domains")]
    fn domains(&self) -> Result<Vec<(String, bool)>, zbus::fdo::Error> {
        Ok(self
            .state()?
            .domains
            .into_iter()
            .map(|domain| (domain.name, domain.route_only))
            .collect())
    }

    #[dbus_interface(property, name = "DefaultRoute")]
    fn default_route(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(self.state()?.effective_default_route())
    }

    #[dbus_interface(property, name = "LLMNR")]
    fn llmnr(&self) -> Result<String, zbus::fdo::Error> {
        Ok(support_mode_string(self.state()?.llmnr).to_owned())
    }

    #[dbus_interface(property, name = "MulticastDNS")]
    fn multicast_dns(&self) -> Result<String, zbus::fdo::Error> {
        Ok(support_mode_string(self.state()?.multicast_dns).to_owned())
    }

    #[dbus_interface(property, name = "DNSOverTLS")]
    fn dns_over_tls(&self) -> Result<String, zbus::fdo::Error> {
        Ok(tls_mode_string(self.state()?.dns_over_tls).to_owned())
    }

    #[dbus_interface(property, name = "DNSSEC")]
    fn dnssec(&self) -> Result<String, zbus::fdo::Error> {
        Ok(validation_mode_string(self.state()?.dnssec).to_owned())
    }

    #[dbus_interface(property, name = "DNSSECNegativeTrustAnchors")]
    fn dnssec_negative_trust_anchors(&self) -> Result<Vec<String>, zbus::fdo::Error> {
        Ok(self.state()?.dnssec_negative_trust_anchors)
    }

    #[dbus_interface(property, name = "DNSSECSupported")]
    fn dnssec_supported(&self) -> bool {
        false
    }
}

impl LinkObject {
    fn state(&self) -> Result<LinkState, DbusError> {
        self.resolver.link(self.ifindex).ok_or_else(|| {
            DbusError::NoSuchLink(format!("no state exists for interface {}", self.ifindex))
        })
    }
}

fn synchronize_link_objects(
    connection: &Connection,
    resolver: &Arc<Resolver>,
    registered: &mut BTreeSet<i32>,
) -> zbus::Result<()> {
    let current = resolver
        .links()
        .into_iter()
        .map(|link| link.ifindex)
        .collect::<BTreeSet<_>>();
    for ifindex in current.difference(registered).copied() {
        let path =
            link_object_path(ifindex).map_err(|error| zbus::Error::Failure(error.to_string()))?;
        connection.object_server().at(
            path.as_str(),
            LinkObject {
                resolver: Arc::clone(resolver),
                ifindex,
            },
        )?;
    }
    for ifindex in registered.difference(&current).copied().collect::<Vec<_>>() {
        let path =
            link_object_path(ifindex).map_err(|error| zbus::Error::Failure(error.to_string()))?;
        connection
            .object_server()
            .remove::<LinkObject, _>(path.as_str())?;
    }
    *registered = current;
    Ok(())
}

fn link_object_path(ifindex: i32) -> Result<OwnedObjectPath, DbusError> {
    if ifindex <= 0 {
        return Err(DbusError::NoSuchLink(format!(
            "invalid interface index {ifindex}"
        )));
    }
    let encoded = encode_bus_label(&ifindex.to_string());
    OwnedObjectPath::try_from(format!("{LINK_PATH_PREFIX}/{encoded}"))
        .map_err(|error| DbusError::InvalidArgs(error.to_string()))
}

fn encode_bus_label(value: &str) -> String {
    if value.is_empty() {
        return "_".to_owned();
    }
    let mut output = String::with_capacity(value.len() * 3);
    for (index, byte) in value.bytes().enumerate() {
        if byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit()) {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "_{byte:02x}");
        }
    }
    output
}

fn validate_lookup_ifindex(ifindex: i32) -> Result<(), DbusError> {
    if ifindex < 0 {
        Err(DbusError::InvalidArgs(format!(
            "invalid interface index {ifindex}"
        )))
    } else {
        Ok(())
    }
}

fn positive_ifindex(ifindex: i32) -> Option<i32> {
    (ifindex > 0).then_some(ifindex)
}

fn validate_family(family: i32) -> Result<(), DbusError> {
    if matches!(family, AF_UNSPEC | AF_INET | AF_INET6) {
        Ok(())
    } else {
        Err(DbusError::InvalidArgs(format!(
            "unsupported address family {family}"
        )))
    }
}

fn decode_address(family: i32, address: &[u8]) -> Result<IpAddr, DbusError> {
    match (family, address) {
        (AF_INET, [a, b, c, d]) => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        (AF_INET6, bytes) if bytes.len() == 16 => {
            let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
                DbusError::InvalidArgs("IPv6 address must contain 16 octets".to_owned())
            })?;
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => Err(DbusError::InvalidArgs(format!(
            "address length does not match family {family}"
        ))),
    }
}

fn decode_dns_servers(
    addresses: Vec<(i32, Vec<u8>)>,
    port: u16,
) -> Result<Vec<SocketAddr>, DbusError> {
    addresses
        .into_iter()
        .map(|(family, address)| {
            decode_address(family, &address).map(|address| SocketAddr::new(address, port))
        })
        .collect()
}

fn address_bytes(address: IpAddr) -> (i32, Vec<u8>) {
    match address {
        IpAddr::V4(address) => (AF_INET, address.octets().to_vec()),
        IpAddr::V6(address) => (AF_INET6, address.octets().to_vec()),
    }
}

fn manager_dns(servers: &[SocketAddr], ifindex: i32) -> Vec<(i32, i32, Vec<u8>)> {
    servers
        .iter()
        .copied()
        .map(|server| manager_dns_entry(ifindex, server))
        .collect()
}
