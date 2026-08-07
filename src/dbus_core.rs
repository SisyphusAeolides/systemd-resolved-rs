// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::config::{DnsServerSpec, Domain, SupportMode, TlsMode, ValidationMode};
use crate::daemon::stop_requested;
use crate::resolver::{AddressLookup, NameLookup, ResolveError, Resolver};
use crate::routing::{LinkError, LinkState};
use crate::wire::{
    extract_answer_records, extract_service_records, Header, CLASS_IN, TYPE_A, TYPE_AAAA, TYPE_SRV,
    TYPE_TXT,
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
    CNameLoop(String),
    #[dbus_error(name = "NoSuchRR")]
    NoSuchResourceRecord(String),
    NoSuchService(String),
    ResourceRecordTypeUnsupported(String),
    NoSuchLink(String),
    LinkBusy(String),
    NetworkDown(String),
    InvalidArgs(String),
    NotSupported(String),
    #[dbus_error(name = "DnsError.FORMERR")]
    DnsFormErr(String),
    #[dbus_error(name = "DnsError.SERVFAIL")]
    DnsServFail(String),
    #[dbus_error(name = "DnsError.NXDOMAIN")]
    DnsNxDomain(String),
    #[dbus_error(name = "DnsError.NOTIMP")]
    DnsNotImp(String),
    #[dbus_error(name = "DnsError.REFUSED")]
    DnsRefused(String),
    #[dbus_error(name = "DnsError.YXDOMAIN")]
    DnsYxDomain(String),
    #[dbus_error(name = "DnsError.YRRSET")]
    DnsYrrset(String),
    #[dbus_error(name = "DnsError.NXRRSET")]
    DnsNxrrset(String),
    #[dbus_error(name = "DnsError.NOTAUTH")]
    DnsNotAuth(String),
    #[dbus_error(name = "DnsError.NOTZONE")]
    DnsNotZone(String),
    #[dbus_error(name = "DnsError.BADVERS")]
    DnsBadVers(String),
    #[dbus_error(name = "DnsError.BADKEY")]
    DnsBadKey(String),
    #[dbus_error(name = "DnsError.BADTIME")]
    DnsBadTime(String),
    #[dbus_error(name = "DnsError.BADMODE")]
    DnsBadMode(String),
    #[dbus_error(name = "DnsError.BADNAME")]
    DnsBadName(String),
    #[dbus_error(name = "DnsError.BADALG")]
    DnsBadAlg(String),
    #[dbus_error(name = "DnsError.BADTRUNC")]
    DnsBadTrunc(String),
    #[dbus_error(name = "DnsError.BADCOOKIE")]
    DnsBadCookie(String),
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
