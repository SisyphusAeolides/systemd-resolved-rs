// SPDX-License-Identifier: LGPL-2.1-or-later
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
        let servers = decode_dns_server_specs(addresses)?;
        self.resolver
            .set_link_dns_specs(ifindex, servers)
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
        manager_dns_ex(&self.resolver.config().configured_upstream_specs(), 0)
    }

    #[dbus_interface(property, name = "FallbackDNS")]
    fn fallback_dns(&self) -> Vec<(i32, i32, Vec<u8>)> {
        manager_dns(&self.resolver.config().configured_fallback_upstreams(), 0)
    }

    #[dbus_interface(property, name = "FallbackDNSEx")]
    fn fallback_dns_ex(&self) -> Vec<(i32, i32, Vec<u8>, u16, String)> {
        manager_dns_ex(&self.resolver.config().configured_fallback_upstream_specs(), 0)
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
            .effective_upstream_specs()
            .first()
            .map_or((0, AF_UNSPEC, Vec::new(), 0, String::new()), |server| {
                manager_dns_ex_entry(0, server)
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
        self.resolver.config().dns_stub_listener.as_str().to_owned()
    }

    #[dbus_interface(property, name = "ResolvConfMode")]
    fn resolv_conf_mode(&self) -> String {
        let config = self.resolver.config();
        crate::resolvconf_publish::system_resolv_conf_mode(&config.runtime_directory)
            .unwrap_or(crate::resolvconf_publish::ResolvConfMode::Foreign)
            .as_str()
            .to_owned()
    }
}
