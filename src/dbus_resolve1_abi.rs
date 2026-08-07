//! Compile-time / test-time ABI inventory for org.freedesktop.resolve1

pub const BUS_NAME: &str = "org.freedesktop.resolve1";
pub const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
pub const MANAGER_IFACE: &str = "org.freedesktop.resolve1.Manager";
pub const LINK_IFACE: &str = "org.freedesktop.resolve1.Link";

/// Manager methods — each needs handler + integration test.
pub const MANAGER_METHODS: &[&str] = &[
    "ResolveHostname",
    "ResolveAddress",
    "ResolveRecord",
    "ResolveService",
    "ResolveDelegateHostname", // newer systemd
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
    "SetLinkDefaultRoute",
    "RevertLink",
    "RegisterService",   // DNS-SD publish if supported
    "UnregisterService",
    "Reload",
    // LogControl1 on separate iface
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
    "ResolvConfMode",
    "ResolvConfPath", // if exposed in your baseline
];

pub const LINK_METHODS: &[&str] = &[
    "SetDNS", "SetDNSEx", "SetDomains", "SetDefaultRoute",
    "SetLLMNR", "SetMulticastDNS", "SetDNSOverTLS", "SetDNSSEC",
    "SetDNSSECNegativeTrustAnchors", "Revert",
];

#[cfg(test)]
mod abi_smoke {
    // Introspect running bus name and assert method set ⊇ MANAGER_METHODS
}
