// SPDX-License-Identifier: LGPL-2.1-or-later
const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NOTIMP: u16 = 4;
const RCODE_BADVERS: u16 = 16;
const MAX_FEATURE_RETRIES: usize = 2;
const MAX_TRANSPORT_RETRIES: usize = 2;

impl Resolver {
    fn preferred_feature_level(&self) -> FeatureLevel {
        if self.config.dnssec == ValidationMode::No {
            FeatureLevel::Edns0
        } else {
            FeatureLevel::DnssecOk
        }
    }

    #[allow(clippy::similar_names, clippy::too_many_lines)]
    fn exchange_with_features(
        &self,
        server: SocketAddr,
        query: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        let configured_best_level = self.preferred_feature_level();
        let mut forced_level = None;
        let mut rcode_probe = false;
        let mut feature_retries = 0usize;
        let mut transport_retries = 0usize;

        loop {
            let path_mtu = self.udp_path_mtu(server);
            let (level, transport, payload_size) = {
                let mut states = self.states();
                let state = states.entry(server).or_default();
                let best_level = if state.missing_root_rrsig
                    && self.config.dnssec != ValidationMode::Yes
                {
                    FeatureLevel::Edns0
                } else {
                    configured_best_level
                };
                let level = forced_level.unwrap_or_else(|| {
                    state
                        .features
                        .possible_level(best_level, Instant::now())
                });
                let payload_size = native::dns_udp_payload_size(
                    path_mtu,
                    server.is_ipv6(),
                    server.ip().is_loopback(),
                    state.transport.packet_fragmented(),
                    state.transport.received_udp_fragment_max(),
                );
                (level, state.transport.mode(), payload_size)
            };
            let outbound = edns::prepare_query(query, level, payload_size)?;

            let (response, response_transport) = match transport {
                TransportMode::Udp => match self.exchange_udp(server, &outbound.packet) {
                    Ok((response, fragment_size)) => {
                        self.record_udp_packet(server, response.len(), fragment_size);
                        let truncated = Header::parse(&response)?.truncated();
                        if udp_requires_tcp_retry(truncated, fragment_size, level) {
                            self.record_transport_success(server, TransportMode::Udp);
                            if truncated {
                                self.record_transport_truncated(server);
                            }
                            match self.exchange_tcp(server, &outbound.packet) {
                                Ok(response) => {
                                    self.record_transport_success(server, TransportMode::Tcp);
                                    (response, TransportMode::Tcp)
                                }
                                Err(error) => {
                                    let (_, failures) = self
                                        .record_transport_failure(server, TransportMode::Tcp);
                                    if failures >= TRANSPORT_RETRY_ATTEMPTS
                                        && level > FeatureLevel::Udp
                                        && self.config.dnssec != ValidationMode::Yes
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
                            && self.config.dnssec != ValidationMode::Yes
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
                },
                TransportMode::Tcp => match self.exchange_tcp(server, &outbound.packet) {
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
                },
            };

            let opt = edns::inspect_opt(&response)?;
            let rcode = edns::full_rcode(&response, opt.as_ref())?;

            if outbound.managed_opt && outbound.sent_edns {
                let Some(opt) = opt.as_ref() else {
                    if self.config.dnssec == ValidationMode::Yes {
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
                    if self.config.dnssec == ValidationMode::Yes {
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
                    if self.config.dnssec == ValidationMode::Yes {
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
                let allow_downgrade = self.config.dnssec != ValidationMode::Yes;
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

            if rcode_requests_feature_downgrade(rcode)
                && level > FeatureLevel::Udp
                && self.config.dnssec != ValidationMode::Yes
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
                let verified_level = if response_transport == TransportMode::Udp {
                    level
                } else {
                    FeatureLevel::Udp
                };
                state.features.record_success(verified_level);
            }
            return edns::response_for_client(query, &response).map_err(ResolveError::from);
        }
    }

    fn record_bad_opt(&self, server: SocketAddr, level: FeatureLevel) -> FeatureLevel {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        let lower = state.features.record_bad_opt(level, Instant::now());
        state.transport.clear_failures();
        lower
    }

    fn record_do_off(&self, server: SocketAddr, level: FeatureLevel) -> FeatureLevel {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        let lower = state.features.record_do_off(level, Instant::now());
        state.transport.clear_failures();
        lower
    }

    fn record_missing_root_rrsig(
        &self,
        server: SocketAddr,
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

    fn downgrade_feature(&self, server: SocketAddr, level: FeatureLevel) {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        state.features.downgrade_to(level, Instant::now());
        state.transport.clear_failures();
    }

    fn record_transport_success(&self, server: SocketAddr, mode: TransportMode) {
        let mut states = self.states();
        states
            .entry(server)
            .or_default()
            .transport
            .record_success(mode);
    }

    fn record_transport_failure(
        &self,
        server: SocketAddr,
        mode: TransportMode,
    ) -> (Option<TransportMode>, u8) {
        let mut states = self.states();
        let transport = &mut states.entry(server).or_default().transport;
        let switched = transport.record_failure(mode);
        (switched, transport.failures(mode))
    }

    fn record_transport_truncated(&self, server: SocketAddr) {
        let mut states = self.states();
        states
            .entry(server)
            .or_default()
            .transport
            .record_truncated();
    }

    fn clear_transport_failures(&self, server: SocketAddr) {
        let mut states = self.states();
        states
            .entry(server)
            .or_default()
            .transport
            .clear_failures();
    }

    fn record_udp_packet(&self, server: SocketAddr, dns_size: usize, fragment_size: u32) {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        state
            .transport
            .record_udp_packet(dns_size, fragment_size, server.is_ipv6());
    }
}

fn udp_requires_tcp_retry(truncated: bool, fragment_size: u32, level: FeatureLevel) -> bool {
    truncated || (fragment_size != 0 && level > FeatureLevel::Udp)
}

fn rcode_requests_feature_downgrade(rcode: u16) -> bool {
    matches!(rcode, RCODE_FORMERR | RCODE_SERVFAIL | RCODE_NOTIMP)
}
