impl Resolver {
    pub fn lookup_address(&self, address: IpAddr) -> Result<AddressLookup, ResolveError> {
        self.lookup_address_on_link(address, None)
    }

    pub fn lookup_address_on_link(
        &self,
        address: IpAddr,
        ifindex: Option<i32>,
    ) -> Result<AddressLookup, ResolveError> {
        let (response, _) =
            self.query_following_redirects(
                &reverse_name(address),
                wire::CLASS_IN,
                TYPE_PTR,
                ifindex,
            )?;
        let names = extract_ptr_names(&response)?;
        if names.is_empty() {
            Err(ResolveError::NoSuchResourceRecord)
        } else {
            Ok(AddressLookup { names, flags: 0 })
        }
    }

    pub fn resolve_record(&self, name: &str, rr_type: u16) -> Result<Vec<u8>, ResolveError> {
        self.resolve_record_with_class(name, wire::CLASS_IN, rr_type)
    }

    pub fn resolve_record_with_class(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
    ) -> Result<Vec<u8>, ResolveError> {
        self.resolve_record_on_link(name, class, rr_type, None)
    }

    pub fn resolve_record_on_link(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
    ) -> Result<Vec<u8>, ResolveError> {
        self.query_following_redirects(name, class, rr_type, ifindex)
            .map(|(response, _)| response)
    }

    pub fn reload_hosts(&self) -> io::Result<()> {
        let hosts = if self.config.read_etc_hosts {
            Hosts::load(&self.config.hosts_path)?
        } else {
            Hosts::default()
        };
        *self.hosts_mut() = hosts;
        crate::static_records::invalidate_system();
        Ok(())
    }

    pub fn flush_cache(&self) {
        self.cache.flush();
    }

    pub fn reset_server_features(&self) {
        for state in self.states().values_mut() {
            state.metric = ServerMetric::default();
            state.cooldown_until = None;
            state.features.reset();
            state.tls = TlsCapability::default();
            state.transport.reset();
            state.missing_root_rrsig = false;
            state.packet_do_off = false;
            state.packet_invalid = false;
        }
    }

    pub fn reset_statistics(&self) {
        self.counters.transactions.store(0, Ordering::Relaxed);
        self.counters.timeouts.store(0, Ordering::Relaxed);
        self.counters
            .timeouts_served_stale
            .store(0, Ordering::Relaxed);
        self.counters
            .failures_served_stale
            .store(0, Ordering::Relaxed);
        self.counters.cache_hits.store(0, Ordering::Relaxed);
        self.counters.cache_misses.store(0, Ordering::Relaxed);
        self.counters.failures.store(0, Ordering::Relaxed);
        self.counters.local_answers.store(0, Ordering::Relaxed);
    }

    pub fn stats(&self) -> ResolverStats {
        ResolverStats {
            current_transactions: self
                .counters
                .current_transactions
                .load(Ordering::Relaxed),
            transactions: self.counters.transactions.load(Ordering::Relaxed),
            timeouts: self.counters.timeouts.load(Ordering::Relaxed),
            timeouts_served_stale: self
                .counters
                .timeouts_served_stale
                .load(Ordering::Relaxed),
            failures_served_stale: self
                .counters
                .failures_served_stale
                .load(Ordering::Relaxed),
            cache_hits: self.counters.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.counters.cache_misses.load(Ordering::Relaxed),
            failures: self.counters.failures.load(Ordering::Relaxed),
            local_answers: self.counters.local_answers.load(Ordering::Relaxed),
            cache_entries: self.cache.len(),
        }
    }
}

#[derive(Debug)]
struct ServerStateDescriptor {
    key: ServerKey,
    spec: DnsServerSpec,
    server_type: &'static str,
    interface: Option<String>,
    interface_index: Option<i32>,
    dnssec_mode: ValidationMode,
    dns_over_tls_mode: TlsMode,
}

impl Resolver {
    pub fn cache_snapshot(&self) -> Vec<crate::cache::CacheSnapshot> {
        self.cache.snapshot()
    }

    pub fn server_state_snapshot(&self) -> Vec<ResolverServerState> {
        let mut descriptors = Vec::new();
        extend_server_state_descriptors(
            &mut descriptors,
            ScopeKind::Global,
            self.config.configured_upstream_specs(),
            "system",
            None,
            self.config.dnssec,
            self.config.dns_over_tls,
        );
        extend_server_state_descriptors(
            &mut descriptors,
            ScopeKind::Fallback,
            self.config.configured_fallback_upstream_specs(),
            "fallback",
            None,
            self.config.dnssec,
            self.config.dns_over_tls,
        );
        for link in self.links() {
            let interface = link
                .kernel
                .as_ref()
                .map(|kernel| kernel.ifname.clone());
            extend_server_state_descriptors(
                &mut descriptors,
                ScopeKind::Link(link.ifindex),
                self.link_dns_specs(link.ifindex),
                "link",
                Some((interface, link.ifindex)),
                link.dnssec,
                link.dns_over_tls,
            );
        }

        let states = self.states();
        descriptors
            .into_iter()
            .map(|descriptor| {
                let default_state = ServerState::default();
                let state = states.get(&descriptor.key).unwrap_or(&default_state);
                let verified_tls = descriptor.dns_over_tls_mode != TlsMode::No
                    && state.tls.verified();
                let possible_tls = descriptor.dns_over_tls_mode != TlsMode::No
                    && state.tls.current_possible();
                let failed_tcp_attempts = state.transport.failures(TransportMode::Tcp);
                let dnssec_supported = descriptor.dnssec_mode == ValidationMode::Yes
                    || (!state.features.bad_opt()
                        && !state.missing_root_rrsig
                        && !state.packet_do_off
                        && failed_tcp_attempts < TRANSPORT_RETRY_ATTEMPTS);

                let best_feature_level = if descriptor.dnssec_mode == ValidationMode::No {
                    FeatureLevel::Edns0
                } else {
                    FeatureLevel::DnssecOk
                };
                let possible_feature_level = state
                    .features
                    .current_possible_level()
                    .min(best_feature_level);
                let verified_feature_level = if state.features.has_verified_level() {
                    resolver_feature_level_name(
                        state.features.verified_level(),
                        state.transport.mode(),
                        verified_tls,
                    )
                } else {
                    "n/a"
                };

                ResolverServerState {
                    server: format_server_spec(&descriptor.spec),
                    server_type: descriptor.server_type.to_owned(),
                    interface: descriptor.interface,
                    interface_index: descriptor.interface_index,
                    verified_feature_level: verified_feature_level.to_owned(),
                    possible_feature_level: resolver_feature_level_name(
                        possible_feature_level,
                        state.transport.mode(),
                        possible_tls,
                    )
                    .to_owned(),
                    dnssec_mode: resolver_validation_mode_name(descriptor.dnssec_mode).to_owned(),
                    dnssec_supported,
                    received_udp_fragment_max: state.transport.received_udp_fragment_max(),
                    failed_udp_attempts: state.transport.failures(TransportMode::Udp),
                    failed_tcp_attempts,
                    packet_truncated: state.transport.packet_truncated(),
                    packet_bad_opt: state.features.bad_opt(),
                    packet_rrsig_missing: state.missing_root_rrsig,
                    packet_invalid: state.packet_invalid,
                    packet_do_off: state.packet_do_off,
                }
            })
            .collect()
    }
}

fn extend_server_state_descriptors(
    output: &mut Vec<ServerStateDescriptor>,
    scope: ScopeKind,
    specs: Vec<DnsServerSpec>,
    server_type: &'static str,
    link: Option<(Option<String>, i32)>,
    dnssec_mode: ValidationMode,
    dns_over_tls_mode: TlsMode,
) {
    let keys = server_keys_for_specs(scope, &specs);
    output.extend(keys.into_iter().zip(specs).map(|(key, spec)| {
        let (interface, interface_index) = link
            .as_ref()
            .map_or((None, None), |(interface, ifindex)| {
                (
                    interface.clone().or_else(|| spec.interface.clone()),
                    Some(*ifindex),
                )
            });
        ServerStateDescriptor {
            key,
            spec,
            server_type,
            interface,
            interface_index,
            dnssec_mode,
            dns_over_tls_mode,
        }
    }));
}

fn format_server_spec(spec: &DnsServerSpec) -> String {
    let address = spec.address;
    let mut output = if address.port() == 53 {
        address.ip().to_string()
    } else if address.is_ipv6() {
        format!("[{}]:{}", address.ip(), address.port())
    } else {
        format!("{}:{}", address.ip(), address.port())
    };
    if let Some(interface) = &spec.interface {
        output.push('%');
        output.push_str(interface);
    }
    if let Some(server_name) = &spec.server_name {
        output.push('#');
        output.push_str(server_name);
    }
    output
}

const fn resolver_feature_level_name(
    level: FeatureLevel,
    transport: TransportMode,
    tls: bool,
) -> &'static str {
    if tls {
        return if matches!(level, FeatureLevel::DnssecOk) {
            "TLS+EDNS0+DO"
        } else {
            "TLS+EDNS0"
        };
    }
    match level {
        FeatureLevel::DnssecOk => "UDP+EDNS0+DO",
        FeatureLevel::Edns0 => "UDP+EDNS0",
        FeatureLevel::Udp if matches!(transport, TransportMode::Tcp) => "TCP",
        FeatureLevel::Udp => "UDP",
    }
}

const fn resolver_validation_mode_name(mode: ValidationMode) -> &'static str {
    match mode {
        ValidationMode::No => "no",
        ValidationMode::AllowDowngrade => "allow-downgrade",
        ValidationMode::Yes => "yes",
    }
}
