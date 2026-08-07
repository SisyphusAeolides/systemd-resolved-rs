// SPDX-License-Identifier: LGPL-2.1-or-later
const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NOTIMP: u16 = 4;
const RCODE_BADVERS: u16 = 16;
const EDNS_OPTION_EXTENDED_ERROR: u16 = 15;
const EDE_NOT_READY: u16 = 14;
const MAX_FEATURE_RETRIES: usize = 2;
const MAX_TRANSPORT_RETRIES: usize = 2;

impl Resolver {
    fn preferred_feature_level(dnssec_mode: ValidationMode) -> FeatureLevel {
        if dnssec_mode == ValidationMode::No {
            FeatureLevel::Edns0
        } else {
            FeatureLevel::DnssecOk
        }
    }

    #[allow(clippy::similar_names, clippy::too_many_lines)]
    fn exchange_with_features(
        &self,
        server: ServerKey,
        query: &[u8],
        budget: &mut DnsAttemptBudget,
    ) -> Result<Vec<u8>, ResolveError> {
        let dnssec_mode = self.server_dnssec_mode(server);
        let configured_best_level = Self::preferred_feature_level(dnssec_mode);
        let tls_mode = self.server_dns_over_tls_mode(server);
        let strict_tls = tls_mode == TlsMode::Yes;
        let mut forced_level = None;
        let mut rcode_probe = false;
        let mut servfail_retried = false;
        let mut feature_retries = 0usize;
        let mut transport_retries = 0usize;

        loop {
            let address = server.server();
            let use_tls = tls_mode != TlsMode::No && self.tls_possible(server, strict_tls);
            let path_mtu = if use_tls {
                None
            } else {
                self.udp_path_mtu(server)
            };
            let (level, transport, payload_size) = {
                let mut states = self.states();
                let state = states.entry(server).or_default();
                let best_level = if state.missing_root_rrsig
                    && dnssec_mode != ValidationMode::Yes
                {
                    FeatureLevel::Edns0
                } else {
                    configured_best_level
                };
                let level = forced_level.unwrap_or_else(|| {
                    state.features.possible_level(best_level, Instant::now())
                });
                let payload_size = native::dns_udp_payload_size(
                    path_mtu,
                    address.is_ipv6(),
                    address.ip().is_loopback(),
                    state.transport.packet_fragmented(),
                    state.transport.received_udp_fragment_max(),
                );
                (level, state.transport.mode(), payload_size)
            };
            let outbound = edns::prepare_query(query, level, payload_size)?;
            let remaining = budget.begin_attempt()?;

            let (response, response_transport, via_tls) = if use_tls {
                match self.exchange_tls(server, &outbound.packet, remaining, strict_tls) {
                    Ok(response) => {
                        self.record_tls_success(server);
                        (response, TransportMode::Tcp, true)
                    }
                    Err(error) => {
                        let transport_failure = matches!(&error, ResolveError::Io(_));
                        if transport_failure {
                            self.record_tls_failure(server, strict_tls);
                            if !strict_tls {
                                continue;
                            }
                        }
                        return Err(error);
                    }
                }
            } else {
                let (response, response_transport) = match transport {
                    TransportMode::Udp => {
                        match self.exchange_udp(server, &outbound.packet, remaining) {
                            Ok((response, fragment_size)) => {
                                self.record_udp_packet(server, response.len(), fragment_size);
                                let truncated = Header::parse(&response)?.truncated();
                                if udp_requires_tcp_retry(truncated, fragment_size, level) {
                                    self.record_transport_success(server, TransportMode::Udp);
                                    if truncated {
                                        self.record_transport_truncated(server);
                                    }
                                    match self.exchange_tcp(
                                        server,
                                        &outbound.packet,
                                        budget.remaining()?,
                                    ) {
                                        Ok(response) => {
                                            self.record_transport_success(server, TransportMode::Tcp);
                                            (response, TransportMode::Tcp)
                                        }
                                        Err(error) => {
                                            let (_, failures) = self
                                                .record_transport_failure(server, TransportMode::Tcp);
                                            if failures >= TRANSPORT_RETRY_ATTEMPTS
                                                && level > FeatureLevel::Udp
                                                && dnssec_mode != ValidationMode::Yes
                                                && feature_retries < MAX_FEATURE_RETRIES
                                            {
                                                let lower = level.lower();
                                                self.downgrade_feature(server, lower);
                                                feature_retries += 1;
                                                forced_level = Some(lower);
                                                continue;
                                            }
                                            return Err(error);
                                        }
                                    }
                                } else {
                                    self.record_transport_success(server, TransportMode::Udp);
                                    (response, TransportMode::Udp)
                                }
                            }
                            Err(error) => {
                                let lower = if outbound.managed_opt
                                    && dnssec_mode != ValidationMode::Yes
                                {
                                    let mut states = self.states();
                                    states
                                        .entry(server)
                                        .or_default()
                                        .features
                                        .record_failure(level, Instant::now())
                                } else {
                                    None
                                };
                                if let Some(lower) =
                                    lower.filter(|_| feature_retries < MAX_FEATURE_RETRIES)
                                {
                                    self.clear_transport_failures(server);
                                    feature_retries += 1;
                                    forced_level = Some(lower);
                                    continue;
                                }

                                if level == FeatureLevel::Udp {
                                    let (switched, _) =
                                      self.record_transport_failure(server, TransportMode::Udp);
                                    if switched == Some(TransportMode::Tcp)
                                    && transport_retries < MAX_TRANSPORT_RETRIES
                                    {
                                        transport_retries += 1;
                                        continue;
                                    }
                                }
                                return Err(error);
                            }
                        }
                    TransportMode::Tcp => {
                        match self.exchange_tcp(server, &outbound.packet, remaining) {
                            Ok(response) => {
                                self.record_transport_success(server, TransportMode::Tcp);
                                (response, TransportMode::Tcp)
                            }
                            Err(error) => {
                                let (switched, _) =
                                    self.record_transport_failure(server, TransportMode::Tcp);
                                if switched == Some(TransportMode::Udp)
                                    && transport_retries < MAX_TRANSPORT_RETRIES
                                {
                                    transport_retries += 1;
                                    continue;
                                }
                                return Err(error);
                            }
                        }
                    }
                };
                (response, response_transport, false)
            };

            let opt = edns::inspect_opt(&response)?;
            let rcode = edns::full_rcode(&response, opt.as_ref())?;

            if outbound.managed_opt && outbound.sent_edns {
                let Some(opt) = opt.as_ref() else {
                    if dnssec_mode == ValidationMode::Yes {
                        return Err(ResolveError::Protocol(
                            "DNS server omitted a required EDNS response",
                        ));
                    }
                    let lower = self.record_bad_opt(server, level);

                    if rcode == 0 || !rcode_requests_feature_downgrade(rcode) {
                        return edns::response_for_client(query, &response)
                            .map_err(ResolveError::from);
                    }

                    if feature_retries < MAX_FEATURE_RETRIES {
                        feature_retries += 1;
                        forced_level = Some(lower);
                        continue;
                    }
                    return edns::response_for_client(query, &response)
                        .map_err(ResolveError::from);
                };

                if opt.version != 0 || rcode == RCODE_BADVERS {
                    if dnssec_mode == ValidationMode::Yes {
                        return Err(ResolveError::Protocol(
                            "DNS server does not support the required EDNS version",
                            ));
                    }
                    let lower = self.record_bad_opt(server, level);
                    if feature_retries < MAX_FEATURE_RETRIES {
                        feature_retries += 1;
                        forced_level = Some(lower);
                        continue;
                    }
                    return edns::response_for_client(query, &response)
                        .map_err(ResolveError::from);
                }

                if level.dnssec_ok() && !opt.dnssec_ok() {
                    if dnssec_mode == ValidationMode::Yes {
                        return Err(ResolveError::Protocol(
                            "DNS server did not echo the EDNS DO flag",
                        ));
                    }
                    let lower = self.record_do_off(server, level);
                    if feature_retries < MAX_FEATURE_RETRIES {
                        feature_retries += 1;
                        forced_level = Some(lower);
                        continue;
                    }
                    return edns::response_for_client(query, &response)
                        .map_err(ResolveError::from);
                }
            }

            if outbound.managed_opt
                && level.dnssec_ok()
                && wire::root_rrsig_missing(&response)?
            {
                let allow_downgrade = dnssec_mode != ValidationMode::Yes;
                let lower = self.record_missing_root_rrsig(server, allow_downgrade);
                if !allow_downgrade {
                    return Err(ResolveError::Protocol(
                        "DNS server omitted required root RRSIG records",
                    ));
                }
                if feature_retries < MAX_FEATURE_RETRIES {
                    feature_retries += 1;
                    forced_level = Some(lower);
                    continue;
                }
                return Err(ResolveError::Protocol(
                    "DNS server repeatedly omitted required root RRSIG records",
                ));
            }

            if rcode == RCODE_SERVFAIL {
                if let Some(ede) = opt.as_ref().map(extended_error_code).transpose()?.flatten() {
                    if ede == EDE_NOT_READY {
                        forced_level = Some(level);
                        continue;
                    }
                    return edns::response_for_client(query, &response)
                        .map_err(ResolveError::from);
                }

                if level > FeatureLevel::Udp
                    && dnssec_mode != ValidationMode::Yes
                    && !servfail_retried
                {
                    servfail_retried = true;
                    forced_level = Some(level);
                    continue;
                }
            }

            if rcode_requests_feature_downgrade(rcode)
                && level > FeatureLevel::Udp
                && dnssec_mode != ValidationMode::Yes
                && feature_retries < MAX_FEATURE_RETRIES
            {
                feature_retries += 1;
                forced_level = Some(level.lower());
                rcode_probe = true;
                continue;
            }

            if outbound.managed_opt {
                let mut states = self.states();
                let state = states.entry(server).or_default();
                if rcode_probe && !rcode_requests_feature_downgrade(rcode) {
                    state.features.downgrade_to(level, Instant::now());
                    state.transport.clear_failures();
                }
                let verified_level = if response_transport == TransportMode::Udp || via_tls {
                    level
                } else {
                    FeatureLevel::Udp
                };
                state.features.record_success(verified_level);
            }
            return edns::response_for_client(query, &response).map_err(ResolveError::from);
        }
    }

    fn tls_possible(&self, server: ServerKey, strict: bool) -> bool {
        let mut states = self.states();
        states
            .entry(server)
            .or_default()
            .tls
            .possible(strict, Instant::now())
    }

    fn record_tls_success(&self, server: ServerKey) {
        let mut states = self.states();
        states.entry(server).or_default().tls.record_success();
    }

    fn record_tls_failure(&self, server: ServerKey, strict: bool) {
        {
            let mut states = self.states();
            states
                .entry(server)
                .or_default()
                .tls
                .record_failure(strict, Instant::now());
        }
        self.tls_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&TlsPoolKey::new(server, strict));
    }

    fn record_bad_opt(&self, server: ServerKey, level: FeatureLevel) -> FeatureLevel {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        let lower = state.features.record_bad_opt(level, Instant::now());
        state.transport.clear_failures();
        lower
    }

    fn record_do_off(&self, server: ServerKey, level: FeatureLevel) -> FeatureLevel {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        let lower = state.features.record_do_off(level, Instant::now());
        state.transport.clear_failures();
        lower
    }

    fn record_missing_root_rrsig(
        &self,
        server: ServerKey,
        allow_downgrade: bool,
    ) -> FeatureLevel {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        state.missing_root_rrsig = true;
        if allow_downgrade {
            state
                .features
                .downgrade_to(FeatureLevel::Edns0, Instant::now());
            state.transport.clear_failures();
        }
        FeatureLevel::Edns0
    }

    fn downgrade_feature(&self, server: ServerKey, level: FeatureLevel) {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        state.features.downgrade_to(level, Instant::now());
        state.transport.clear_failures();
    }

    fn record_transport_success(&self, server: ServerKey, mode: TransportMode) {
        let mut states = self.states();
        states
            .entry(server)
            .or_default()
            .transport
            .record_success(mode);
    }

    fn record_transport_failure(
        &self,
        server: ServerKey,
        mode: TransportMode,
    ) -> (Option<TransportMode>, u8) {
        let mut states = self.states();
        let transport = &mut states.entry(server).or_default().transport;
        let switched = transport.record_failure(mode);
        (switched, transport.failures(mode))
    }

    fn record_transport_truncated(&self, server: ServerKey) {
        let mut states = self.states();
        states
            .entry(server)
            .or_default()
            .transport
            .record_truncated();
    }

    fn clear_transport_failures(&self, server: ServerKey) {
        let mut states = self.states();
        states
            .entry(server)
            .or_default()
            .transport
            .clear_failures();
    }

    fn record_udp_packet(&self, server: ServerKey, dns_size: usize, fragment_size: u32) {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        state.transport.record_udp_packet(
            dns_size,
            fragment_size,
            server.server().is_ipv6(),
        );
    }
}

fn extended_error_code(opt: &edns::OptRecord) -> Result<Option<u16>, WireError> {
    let Some(option) = opt
        .options
        .iter()
        .find(|option| option.code == EDNS_OPTION_EXTENDED_ERROR)
    else {
        return Ok(None);
    };
    let bytes = option.data.get(..2).ok_or(WireError::InvalidRecord)?;
    Ok(Some(u16::from_be_bytes([bytes[0], bytes[1]])))
}

fn udp_requires_tcp_retry(truncated: bool, fragment_size: u32, level: FeatureLevel) -> bool {
    truncated || (fragment_size != 0 && level > FeatureLevel::Udp)
}

fn rcode_requests_feature_downgrade(rcode: u16) -> bool {
    matches!(rcode, RCODE_FORMERR | RCODE_SERVFAIL | RCODE_NOTIMP)
}
