// SPDX-License-Identifier: LGPL-2.1-or-later

const RESOLVE_INTERFACE: &str = include_str!("../src/varlink.rs");
const DNS_CONFIGURATION: &str = include_str!("../src/varlink_dns_configuration.rs");

#[test]
fn resolve_varlink_exposes_pinned_error_identifiers() {
    for identifier in [
        "DNSSECValidationFailed",
        "InconsistentServiceRecords",
        "NoTrustAnchor",
        "QueryAborted",
        "QueryRefused",
        "ResourceRecordTypeObsolete",
        "StubLoop",
    ] {
        assert!(
            RESOLVE_INTERFACE.contains(identifier),
            "missing pinned Resolve Varlink identifier {identifier}"
        );
    }
}

#[test]
fn resolve_varlink_exposes_dns_configuration_schema_and_method() {
    for symbol in [
        "type DNSServer",
        "type SearchDomain",
        "type DNSConfiguration",
        "method DumpDNSConfiguration",
        "io.systemd.Resolve.DumpDNSConfiguration",
    ] {
        assert!(
            RESOLVE_INTERFACE.contains(symbol),
            "missing pinned Resolve Varlink symbol {symbol}"
        );
    }

    for field in [
        "currentServer",
        "fallbackServers",
        "negativeTrustAnchors",
        "dnssecSupported",
        "resolvConfMode",
        "accessible",
        "routeOnly",
    ] {
        assert!(
            DNS_CONFIGURATION.contains(field),
            "missing DNS configuration projection field {field}"
        );
    }
}
