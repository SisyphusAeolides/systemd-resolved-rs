// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(
    clippy::if_not_else,
    clippy::needless_pass_by_value,
    clippy::type_complexity,
    clippy::unused_self,
    clippy::used_underscore_binding
)]
use crate::config::{Domain, SupportMode, TlsMode, ValidationMode};
use crate::daemon::stop_requested;
use crate::resolver::{AddressLookup, NameLookup, ResolveError, Resolver};
use crate::routing::{LinkError, LinkState};
use crate::wire::{
    extract_answer_records, extract_service_records, Header, CLASS_IN, TYPE_SRV, TYPE_TXT,
};
use std::collections::{BTreeSet, HashMap};
use std::convert::TryFrom;
use std::error::Error;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use zbus::blocking::{Connection, ConnectionBuilder};
use zbus::dbus_interface;
use zbus::zvariant::OwnedObjectPath;

const BUS_NAME: &str = "org.freedesktop.resolve1";
const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
const LINK_PATH_PREFIX: &str = "/org/freedesktop/resolve1/link";
const AF_UNSPEC: i32 = 0;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const DNS_PORT: u16 = 53;
const SD_RESOLVED_DNS: u64 = 1 << 0;
const SD_RESOLVED_LLMNR_IPV4: u64 = 1 << 1;
const SD_RESOLVED_LLMNR_IPV6: u64 = 1 << 2;
const SD_RESOLVED_MDNS_IPV4: u64 = 1 << 3;
const SD_RESOLVED_MDNS_IPV6: u64 = 1 << 4;
const SD_RESOLVED_NO_TXT: u64 = 1 << 6;
const SD_RESOLVED_NO_ADDRESS: u64 = 1 << 7;
const SD_RESOLVED_PROTOCOL_DNS: u64 = 1 << 10;

#[derive(Debug)]
pub struct DbusServer {
    resolver: Arc<Resolver>,
}

impl DbusServer {
    pub fn new(resolver: Arc<Resolver>) -> Self {
        Self { resolver }
    }

    pub fn run(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let manager = ManagerObject {
            resolver: Arc::clone(&self.resolver),
        };
        let connection = ConnectionBuilder::system()?
            .name(BUS_NAME)?
            .serve_at(MANAGER_PATH, manager)?
            .build()?;
        let mut registered = BTreeSet::new();

        while !stop_requested() {
            synchronize_link_objects(&connection, &self.resolver, &mut registered)?;
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }
}

#[derive(Debug, zbus::DBusError)]
#[dbus_error(prefix = "org.freedesktop.resolve1")]
enum DbusError {
    #[dbus_error(zbus_error)]
    ZBus(zbus::Error),
    NoNameServers(String),
    InvalidReply(String),
    #[dbus_error(name = "NoSuchRR")]
    NoSuchResourceRecord(String),
    NoSuchService(String),
    ResourceRecordTypeUnsupported(String),
    NoSuchLink(String),
    NetworkDown(String),
    InvalidArgs(String),
    NotSupported(String),
}

impl From<DbusError> for zbus::fdo::Error {
    fn from(error: DbusError) -> Self {
        Self::Failed(error.to_string())
    }
}

#[derive(Debug)]
struct ManagerObject {
    resolver: Arc<Resolver>,
}

#[dbus_interface(name = "org.freedesktop.resolve1.Manager")]
impl ManagerObject {
    #[dbus_interface(out_args("addresses", "canonical", "flags"))]
    fn resolve_hostname(
        &self,
        ifindex: i32,
        name: &str,
        family: i32,
        flags: u64,
    ) -> Result<(Vec<(i32, i32, Vec<u8>)>, String, u64), DbusError> {
        validate_lookup_ifindex(ifindex)?;
        let _ = flags;
        let lookup = self
            .resolver
            .lookup_name_on_link(name, family, positive_ifindex(ifindex))
            .map_err(map_resolve_error)?;
        Ok(name_lookup_reply(lookup, ifindex))
    }

    #[dbus_interface(out_args("names", "flags"))]
    fn resolve_address(
        &self,
        ifindex: i32,
        family: i32,
        address: Vec<u8>,
        flags: u64,
    ) -> Result<(Vec<(i32, String)>, u64), DbusError> {
        validate_lookup_ifindex(ifindex)?;
        let _ = flags;
        let address = decode_address(family, &address)?;
        let lookup = self
            .resolver
            .lookup_address_on_link(address, positive_ifindex(ifindex))
            .map_err(map_resolve_error)?;
        Ok(address_lookup_reply(lookup, ifindex))
    }

    #[dbus_interface(out_args("records", "flags"))]
    fn resolve_record(
        &self,
        ifindex: i32,
        name: &str,
        class: u16,
        r#type: u16,
        flags: u64,
    ) -> Result<(Vec<(i32, u16, u16, Vec<u8>)>, u64), DbusError> {
        validate_lookup_ifindex(ifindex)?;
        let _ = flags;
        let response = self
            .resolver
            .resolve_record_on_link(name, class, r#type, positive_ifindex(ifindex))
            .map_err(map_resolve_error)?;
        let records = extract_answer_records(&response)
            .map_err(|error| DbusError::InvalidReply(error.to_string()))?
            .into_iter()
            .map(|record| (ifindex.max(0), record.class, record.rr_type, record.raw))
            .collect();
        Ok((records, response_flags(&response)))
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    #[dbus_interface(out_args(
        "srv_data",
        "txt_data",
        "canonical_name",
        "canonical_type",
        "canonical_domain",
        "flags"
    ))]
    fn resolve_service(
        &self,
        ifindex: i32,
        name: &str,
        r#type: &str,
        domain: &str,
        family: i32,
        flags: u64,
    ) -> Result<
        (
            Vec<(u16, u16, u16, String, Vec<(i32, i32, Vec<u8>)>, String)>,
            Vec<Vec<u8>>,
            String,
            String,
            String,
            u64,
        ),
        DbusError,
    > {
        validate_lookup_ifindex(ifindex)?;
        validate_family(family)?;
        resolve_service_reply(&self.resolver, ifindex, name, r#type, domain, family, flags)
    }

    #[dbus_interface(out_args("path"))]
    fn get_link(&self, ifindex: i32) -> Result<(OwnedObjectPath,), DbusError> {
        self.resolver.link(ifindex).ok_or_else(|| {
            DbusError::NoSuchLink(format!("no state exists for interface {ifindex}"))
        })?;
        Ok((link_object_path(ifindex)?,))
    }

    #[dbus_interface(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) -> Result<(), DbusError> {
        let servers = decode_dns_servers(addresses, DNS_PORT)?;
        self.resolver
            .set_link_dns(ifindex, servers)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetLinkDNSEx")]
    fn set_link_dns_ex(
        &self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>, u16, String)>,
    ) -> Result<(), DbusError> {
        let mut servers = Vec::with_capacity(addresses.len());
        for (family, address, port, server_name) in addresses {
            if !server_name.is_empty() {
                return Err(DbusError::ResourceRecordTypeUnsupported(
                    "DNS server names require DNS-over-TLS transport support".to_owned(),
                ));
            }
            servers.push(SocketAddr::new(
                decode_address(family, &address)?,
                if port == 0 { DNS_PORT } else { port },
            ));
        }
        self.resolver
            .set_link_dns(ifindex, servers)
            .map_err(map_link_error)
    }

    fn set_link_domains(
        &self,
        ifindex: i32,
        domains: Vec<(String, bool)>,
    ) -> Result<(), DbusError> {
        self.resolver
            .set_link_domains(
                ifindex,
                domains
                    .into_iter()
                    .map(|(name, route_only)| Domain { name, route_only })
                    .collect(),
            )
            .map_err(map_link_error)
    }

    fn set_link_default_route(&self, ifindex: i32, enable: bool) -> Result<(), DbusError> {
        self.resolver
            .set_link_default_route(ifindex, Some(enable))
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetLinkLLMNR")]
    fn set_link_llmnr(&self, ifindex: i32, mode: &str) -> Result<(), DbusError> {
        self.resolver
            .set_link_llmnr(ifindex, parse_support_mode(mode)?)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetLinkMulticastDNS")]
    fn set_link_multicast_dns(&self, ifindex: i32, mode: &str) -> Result<(), DbusError> {
        self.resolver
            .set_link_multicast_dns(ifindex, parse_support_mode(mode)?)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetLinkDNSOverTLS")]
    fn set_link_dns_over_tls(&self, ifindex: i32, mode: &str) -> Result<(), DbusError> {
        self.resolver
            .set_link_dns_over_tls(ifindex, parse_tls_mode(mode)?)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetLinkDNSSEC")]
    fn set_link_dnssec(&self, ifindex: i32, mode: &str) -> Result<(), DbusError> {
        self.resolver
            .set_link_dnssec(ifindex, parse_validation_mode(mode)?)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetLinkDNSSECNegativeTrustAnchors")]
    fn set_link_dnssec_negative_trust_anchors(
        &self,
        ifindex: i32,
        names: Vec<String>,
    ) -> Result<(), DbusError> {
        self.resolver
            .set_link_dnssec_negative_trust_anchors(ifindex, names)
            .map_err(map_link_error)
    }

    fn revert_link(&self, ifindex: i32) -> Result<(), DbusError> {
        self.resolver.revert_link(ifindex).map_err(map_link_error)
    }

    #[allow(clippy::too_many_arguments)]
    #[dbus_interface(out_args("service_path"))]
    fn register_service(
        &self,
        id: &str,
        name_template: &str,
        r#type: &str,
        service_port: u16,
        service_priority: u16,
        service_weight: u16,
        txt_datas: Vec<HashMap<String, Vec<u8>>>,
    ) -> Result<(OwnedObjectPath,), DbusError> {
        let _ = (
            id,
            name_template,
            r#type,
            service_port,
            service_priority,
            service_weight,
            txt_datas,
        );
        Err(DbusError::NotSupported(
            "DNS-SD service registration is not implemented".to_owned(),
        ))
    }

    fn unregister_service(&self, service_path: OwnedObjectPath) -> Result<(), DbusError> {
        let _ = service_path;
        Err(DbusError::NotSupported(
            "DNS-SD service registration is not implemented".to_owned(),
        ))
    }

    #[dbus_interface(out_args("path"))]
    fn get_delegate(&self, id: &str) -> Result<(OwnedObjectPath,), DbusError> {
        Err(DbusError::NoSuchService(format!(
            "no DNS delegate exists for {id}"
        )))
    }

    #[dbus_interface(out_args("delegates"))]
    fn list_delegates(&self) -> (Vec<(String, OwnedObjectPath)>,) {
        (Vec::new(),)
    }

    fn reset_statistics(&self) {
        self.resolver.reset_statistics();
    }

    fn flush_caches(&self) {
        self.resolver.flush_cache();
    }

    fn reset_server_features(&self) {
        self.resolver.reset_server_features();
    }

    #[dbus_interface(property, name = "LLMNRHostname")]
    fn llmnr_hostname(&self) -> String {
        fs::read_to_string("/etc/hostname")
            .map(|name| name.trim().to_owned())
            .ok()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "localhost".to_owned())
    }

    #[dbus_interface(property, name = "LLMNR")]
    fn llmnr(&self) -> String {
        support_mode_string(self.resolver.config().llmnr).to_owned()
    }

    #[dbus_interface(property, name = "MulticastDNS")]
    fn multicast_dns(&self) -> String {
        support_mode_string(self.resolver.config().multicast_dns).to_owned()
    }

    #[dbus_interface(property, name = "DNSOverTLS")]
    fn dns_over_tls(&self) -> String {
        tls_mode_string(self.resolver.config().dns_over_tls).to_owned()
    }

    #[dbus_interface(property, name = "DNS")]
    fn dns(&self) -> Vec<(i32, i32, Vec<u8>)> {
        manager_dns(&self.resolver.config().configured_upstreams(), 0)
    }

    #[dbus_interface(property, name = "DNSEx")]
    fn dns_ex(&self) -> Vec<(i32, i32, Vec<u8>, u16, String)> {
        manager_dns_ex(&self.resolver.config().configured_upstreams(), 0)
    }

    #[dbus_interface(property, name = "FallbackDNS")]
    fn fallback_dns(&self) -> Vec<(i32, i32, Vec<u8>)> {
        manager_dns(&self.resolver.config().configured_fallback_upstreams(), 0)
    }

    #[dbus_interface(property, name = "FallbackDNSEx")]
    fn fallback_dns_ex(&self) -> Vec<(i32, i32, Vec<u8>, u16, String)> {
        manager_dns_ex(&self.resolver.config().configured_fallback_upstreams(), 0)
    }

    #[dbus_interface(property, name = "CurrentDNSServer")]
    fn current_dns_server(&self) -> (i32, i32, Vec<u8>) {
        self.resolver
            .config()
            .effective_upstreams()
            .first()
            .map_or((0, AF_UNSPEC, Vec::new()), |server| {
                manager_dns_entry(0, *server)
            })
    }

    #[dbus_interface(property, name = "CurrentDNSServerEx")]
    fn current_dns_server_ex(&self) -> (i32, i32, Vec<u8>, u16, String) {
        self.resolver
            .config()
            .effective_upstreams()
            .first()
            .map_or((0, AF_UNSPEC, Vec::new(), 0, String::new()), |server| {
                manager_dns_ex_entry(0, *server)
            })
    }

    #[dbus_interface(property, name = "Domains")]
    fn domains(&self) -> Vec<(i32, String, bool)> {
        let mut domains = self
            .resolver
            .config()
            .domains
            .iter()
            .map(|domain| (0, domain.name.clone(), domain.route_only))
            .collect::<Vec<_>>();
        for link in self.resolver.links() {
            domains.extend(
                link.domains
                    .into_iter()
                    .map(|domain| (link.ifindex, domain.name, domain.route_only)),
            );
        }
        domains
    }

    #[dbus_interface(property, name = "TransactionStatistics")]
    fn transaction_statistics(&self) -> (u64, u64) {
        let transactions = self.resolver.stats().transactions;
        (0, transactions)
    }

    #[dbus_interface(property, name = "CacheStatistics")]
    fn cache_statistics(&self) -> (u64, u64, u64) {
        let stats = self.resolver.stats();
        (
            u64::try_from(stats.cache_entries).unwrap_or(u64::MAX),
            stats.cache_hits,
            stats.cache_misses,
        )
    }

    #[dbus_interface(property, name = "DNSSEC")]
    fn dnssec(&self) -> String {
        validation_mode_string(self.resolver.config().dnssec).to_owned()
    }

    #[dbus_interface(property, name = "DNSSECStatistics")]
    fn dnssec_statistics(&self) -> (u64, u64, u64, u64) {
        (0, 0, 0, 0)
    }

    #[dbus_interface(property, name = "DNSSECSupported")]
    fn dnssec_supported(&self) -> bool {
        false
    }

    #[dbus_interface(property, name = "DNSSECNegativeTrustAnchors")]
    fn dnssec_negative_trust_anchors(&self) -> Vec<String> {
        Vec::new()
    }

    #[dbus_interface(property, name = "DNSStubListener")]
    fn dns_stub_listener(&self) -> String {
        if self.resolver.config().listeners.is_empty()
            && self.resolver.config().proxy_listeners.is_empty()
        {
            "no".to_owned()
        } else {
            "yes".to_owned()
        }
    }

    #[dbus_interface(property, name = "ResolvConfMode")]
    fn resolv_conf_mode(&self) -> String {
        "stub".to_owned()
    }
}

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
        let mut servers = Vec::with_capacity(addresses.len());
        for (family, address, port, server_name) in addresses {
            if !server_name.is_empty() {
                return Err(DbusError::ResourceRecordTypeUnsupported(
                    "DNS server names require DNS-over-TLS transport support".to_owned(),
                ));
            }
            servers.push(SocketAddr::new(
                decode_address(family, &address)?,
                if port == 0 { DNS_PORT } else { port },
            ));
        }
        self.resolver
            .set_link_dns(self.ifindex, servers)
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
    fn dns_ex(&self) -> Result<Vec<(i32, Vec<u8>, u16, String)>, zbus::fdo::Error> {
        Ok(self
            .state()?
            .dns_servers
            .into_iter()
            .map(link_dns_ex_entry)
            .collect())
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
    fn current_dns_server_ex(&self) -> Result<(i32, Vec<u8>, u16, String), zbus::fdo::Error> {
        Ok(self
            .state()?
            .dns_servers
            .first()
            .copied()
            .map_or((AF_UNSPEC, Vec::new(), 0, String::new()), link_dns_ex_entry))
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

fn manager_dns_entry(ifindex: i32, server: SocketAddr) -> (i32, i32, Vec<u8>) {
    let (family, address) = address_bytes(server.ip());
    (ifindex, family, address)
}

fn manager_dns_ex(servers: &[SocketAddr], ifindex: i32) -> Vec<(i32, i32, Vec<u8>, u16, String)> {
    servers
        .iter()
        .copied()
        .map(|server| manager_dns_ex_entry(ifindex, server))
        .collect()
}

fn manager_dns_ex_entry(ifindex: i32, server: SocketAddr) -> (i32, i32, Vec<u8>, u16, String) {
    let (family, address) = address_bytes(server.ip());
    (ifindex, family, address, server.port(), String::new())
}

fn link_dns_entry(server: SocketAddr) -> (i32, Vec<u8>) {
    address_bytes(server.ip())
}

fn link_dns_ex_entry(server: SocketAddr) -> (i32, Vec<u8>, u16, String) {
    let (family, address) = address_bytes(server.ip());
    (family, address, server.port(), String::new())
}

fn name_lookup_reply(lookup: NameLookup, ifindex: i32) -> (Vec<(i32, i32, Vec<u8>)>, String, u64) {
    let addresses = lookup
        .addresses
        .into_iter()
        .map(|address| {
            let (family, bytes) = address_bytes(address);
            (ifindex.max(0), family, bytes)
        })
        .collect();
    (
        addresses,
        lookup.canonical_name,
        lookup.flags | SD_RESOLVED_PROTOCOL_DNS,
    )
}

fn address_lookup_reply(lookup: AddressLookup, ifindex: i32) -> (Vec<(i32, String)>, u64) {
    (
        lookup
            .names
            .into_iter()
            .map(|name| (ifindex.max(0), name))
            .collect(),
        lookup.flags | SD_RESOLVED_PROTOCOL_DNS,
    )
}

fn response_flags(response: &[u8]) -> u64 {
    Header::parse(response).map_or(SD_RESOLVED_PROTOCOL_DNS, |header| {
        let authenticated = if header.flags & 0x0020 != 0 {
            1 << 9
        } else {
            0
        };
        SD_RESOLVED_PROTOCOL_DNS | authenticated
    })
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn resolve_service_reply(
    resolver: &Resolver,
    ifindex: i32,
    name: &str,
    service_type: &str,
    domain: &str,
    family: i32,
    flags: u64,
) -> Result<
    (
        Vec<(u16, u16, u16, String, Vec<(i32, i32, Vec<u8>)>, String)>,
        Vec<Vec<u8>>,
        String,
        String,
        String,
        u64,
    ),
    DbusError,
> {
    let (owner, canonical_name, canonical_type, canonical_domain) =
        service_owner(name, service_type, domain)?;
    let response = resolver
        .resolve_record_on_link(&owner, CLASS_IN, TYPE_SRV, positive_ifindex(ifindex))
        .map_err(map_resolve_error)?;
    let records = extract_service_records(&response)
        .map_err(|error| DbusError::InvalidReply(error.to_string()))?;
    let mut services = Vec::new();
    let mut root_target = false;
    let mut last_error = None;

    for record in records.srv {
        if record.target.text() == "." {
            root_target = true;
            continue;
        }
        let mut addresses = Vec::new();
        let mut canonical = String::new();
        if flags & SD_RESOLVED_NO_ADDRESS == 0 {
            match resolver.lookup_name_on_link(
                record.target.text(),
                family,
                positive_ifindex(ifindex),
            ) {
                Ok(lookup) => {
                    canonical = lookup.canonical_name;
                    addresses = lookup
                        .addresses
                        .into_iter()
                        .map(|address| {
                            let (family, bytes) = address_bytes(address);
                            (ifindex.max(0), family, bytes)
                        })
                        .collect();
                }
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            }
        }
        services.push((
            record.priority,
            record.weight,
            record.port,
            record.target.text().to_owned(),
            addresses,
            canonical,
        ));
    }

    if services.is_empty() {
        if root_target {
            return Err(DbusError::NoSuchService(
                "service is explicitly not provided".to_owned(),
            ));
        }
        if let Some(error) = last_error {
            return Err(map_resolve_error(error));
        }
        return Err(DbusError::NoSuchService("service was not found".to_owned()));
    }

    let txt_data = if flags & SD_RESOLVED_NO_TXT != 0 {
        Vec::new()
    } else {
        match resolver.resolve_record_on_link(&owner, CLASS_IN, TYPE_TXT, positive_ifindex(ifindex))
        {
            Ok(response) => {
                extract_service_records(&response)
                    .map_err(|error| DbusError::InvalidReply(error.to_string()))?
                    .txt
            }
            Err(ResolveError::NoSuchResourceRecord) => Vec::new(),
            Err(error) => return Err(map_resolve_error(error)),
        }
    };

    Ok((
        services,
        txt_data,
        canonical_name,
        canonical_type,
        canonical_domain,
        response_flags(&response),
    ))
}

fn service_owner(
    name: &str,
    service_type: &str,
    domain: &str,
) -> Result<(String, String, String, String), DbusError> {
    let name = name.trim_end_matches('.');
    let service_type = service_type.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() || !service_type_is_valid(service_type) {
        return Err(DbusError::InvalidArgs(
            "invalid service type or domain".to_owned(),
        ));
    }
    if !name.is_empty() && !service_instance_is_valid(name) {
        return Err(DbusError::InvalidArgs(
            "invalid service instance name".to_owned(),
        ));
    }
    let owner = if name.is_empty() {
        format!("{service_type}.{domain}")
    } else {
        format!("{name}.{service_type}.{domain}")
    };
    Ok((
        owner,
        name.to_owned(),
        service_type.to_ascii_lowercase(),
        domain.to_ascii_lowercase(),
    ))
}

fn service_instance_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.is_ascii()
        && !value.bytes().any(|byte| matches!(byte, b'.' | 0))
}

fn service_type_is_valid(value: &str) -> bool {
    let mut labels = value.split('.');
    let Some(service) = labels.next() else {
        return false;
    };
    let Some(protocol) = labels.next() else {
        return false;
    };
    labels.next().is_none() && valid_service_label(service) && valid_service_label(protocol)
}

fn valid_service_label(value: &str) -> bool {
    value.starts_with('_')
        && value.len() > 1
        && value.len() <= 63
        && value.is_ascii()
        && value
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn parse_support_mode(value: &str) -> Result<SupportMode, DbusError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "yes" | "true" | "on" | "1" => Ok(SupportMode::Yes),
        "resolve" => Ok(SupportMode::Resolve),
        "no" | "false" | "off" | "0" => Ok(SupportMode::No),
        _ => Err(DbusError::InvalidArgs(format!(
            "invalid resolver support mode {value}"
        ))),
    }
}

fn parse_tls_mode(value: &str) -> Result<TlsMode, DbusError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "no" | "false" | "off" | "0" => Ok(TlsMode::No),
        "opportunistic" => Ok(TlsMode::Opportunistic),
        "yes" | "true" | "on" | "1" => Ok(TlsMode::Yes),
        _ => Err(DbusError::InvalidArgs(format!(
            "invalid DNS-over-TLS mode {value}"
        ))),
    }
}

fn parse_validation_mode(value: &str) -> Result<ValidationMode, DbusError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "allow-downgrade" => Ok(ValidationMode::AllowDowngrade),
        "no" | "false" | "off" | "0" => Ok(ValidationMode::No),
        "yes" | "true" | "on" | "1" => Ok(ValidationMode::Yes),
        _ => Err(DbusError::InvalidArgs(format!(
            "invalid DNSSEC mode {value}"
        ))),
    }
}

const fn support_mode_string(mode: SupportMode) -> &'static str {
    match mode {
        SupportMode::No => "no",
        SupportMode::Resolve => "resolve",
        SupportMode::Yes => "yes",
    }
}

const fn tls_mode_string(mode: TlsMode) -> &'static str {
    match mode {
        TlsMode::No => "no",
        TlsMode::Opportunistic => "opportunistic",
        TlsMode::Yes => "yes",
    }
}

const fn validation_mode_string(mode: ValidationMode) -> &'static str {
    match mode {
        ValidationMode::No => "no",
        ValidationMode::AllowDowngrade => "allow-downgrade",
        ValidationMode::Yes => "yes",
    }
}

fn map_link_error(error: LinkError) -> DbusError {
    match error {
        LinkError::NoSuchLink(_) | LinkError::InvalidIfindex(_) => {
            DbusError::NoSuchLink(error.to_string())
        }
        LinkError::InvalidDomain(_) => DbusError::InvalidArgs(error.to_string()),
    }
}

fn map_resolve_error(error: ResolveError) -> DbusError {
    match error {
        ResolveError::NoNameServers => DbusError::NoNameServers(error.to_string()),
        ResolveError::NoSuchResourceRecord => DbusError::NoSuchResourceRecord(error.to_string()),
        ResolveError::Link(link) => map_link_error(link),
        ResolveError::UnsupportedFamily(_) => DbusError::InvalidArgs(error.to_string()),
        ResolveError::Io(_) => DbusError::NetworkDown(error.to_string()),
        ResolveError::Wire(_) | ResolveError::Protocol(_) => {
            DbusError::InvalidReply(error.to_string())
        }
    }
}

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
}
