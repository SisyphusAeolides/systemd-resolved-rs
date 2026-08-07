//! org.freedesktop.resolve1 ABI inventory + dispatch hooks.
//! Wire each method to resolver/supremacy/llmnr/mdns.

pub const BUS_NAME: &str = "org.freedesktop.resolve1";
pub const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
pub const MANAGER_IFACE: &str = "org.freedesktop.resolve1.Manager";
pub const LINK_IFACE: &str = "org.freedesktop.resolve1.Link";

pub const MANAGER_METHODS: &[&str] = &[
    "ResolveHostname",
    "ResolveAddress",
    "ResolveRecord",
    "ResolveService",
    "ResetStatistics",
    "FlushCaches",
    "ResetServerFeatures",
    "GetLink",
    "SetLinkDNS",
    "SetLinkDNSEx",
    "SetLinkDomains",
    "SetLinkDefaultRoute",
    "SetLinkLLMNR",
    "SetLinkMulticastDNS",
    "SetLinkDNSOverTLS",
    "SetLinkDNSSEC",
    "SetLinkDNSSECNegativeTrustAnchors",
    "RevertLink",
    "Reload",
];

pub const MANAGER_PROPERTIES: &[&str] = &[
    "LLMNRHostname",
    "LLMNR",
    "MulticastDNS",
    "DNSOverTLS",
    "DNS",
    "DNSEx",
    "FallbackDNS",
    "CurrentDNSServer",
    "CurrentDNSServerEx",
    "Domains",
    "TransactionStatistics",
    "CacheStatistics",
    "DNSSECStatistics",
    "DNSSECSupported",
    "DNSSECNegativeTrustAnchors",
    "DNSSEC",
];

/// Result codes roughly matching resolve1
#[derive(Clone, Copy, Debug)]
#[repr(i32)]
pub enum Resolve1Error {
    Success = 0,
    NoName = 1,
    NoAddress = 2,
    DnsTimeout = 3,
    DnsNoServer = 4,
    DnssecFailed = 5,
    NoSuchLink = 6,
    NotSupported = 7,
}

#[derive(Clone, Debug)]
pub struct ResolveHostnameArgs {
    pub ifindex: i32,
    pub name: String,
    pub family: i32, // AF_INET=2 AF_INET6=10 AF_UNSPEC=0
    pub flags: u64,
}

#[derive(Clone, Debug)]
pub struct ResolveHostnameResult {
    pub addrs: Vec<(i32 /*ifindex*/, i32 /*family*/, Vec<u8> /*addr*/)>,
    pub canonical: String,
    pub flags: u64,
}

/// Implement body in dbus_manager — this is the contract.
pub trait Resolve1Manager: Send + Sync {
    fn resolve_hostname(
        &self,
        a: ResolveHostnameArgs,
    ) -> Result<ResolveHostnameResult, Resolve1Error>;
    fn flush_caches(&self);
    fn reset_statistics(&self);
    fn reset_server_features(&self);
    fn reload(&self);
}
