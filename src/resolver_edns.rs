// SPDX-License-Identifier: LGPL-2.1-or-later
const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NOTIMP: u16 = 4;
const RCODE_BADVERS: u16 = 16;
const MAX_FEATURE_RETRIES: usize = 3;

impl Resolver {
    fn preferred_feature_level(&self) -> FeatureLevel {
        if self.config.dnssec == ValidationMode::No {
            FeatureLevel::Edns0
        } else {
            FeatureLevel::DnssecOk
        }
    }

    fn exchange_with_features(
        &self,
        server: SocketAddr,
        query: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        let preferred = self.preferred_feature_level();
        let mut forced_level = None;
        let mut rcode_probe = false;
        let mut feature_retries = 0usize;

        loop {
            let level = {
                let mut states = self.states();
                forced_level.unwrap_or_else(|| {
                    states
                        .entry(server)
                        .or_default()
                        .features
                        .possible_level(preferred, Instant::now())
                })
            };
            let prepared =
                edns::prepare_query(query, level, edns::DEFAULT_UDP_PAYLOAD_SIZE)?;

            let response = match self.exchange(server, &prepared.packet) {
                Ok(response) => response,
                Err(error) => {
                    let lower = if prepared.managed_opt {
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
                        feature_retries += 1;
                        forced_level = Some(lower);
                        continue;
                    }
                    return Err(error);
                }
            };

            let opt = edns::inspect_opt(&response)?;
            let rcode = edns::full_rcode(&response, opt.as_ref())?;

            if prepared.managed_opt && prepared.sent_edns {
                let Some(opt) = opt.as_ref() else {
                    if self.config.dnssec == ValidationMode::Yes {
                        return Err(ResolveError::Protocol(
                            "DNS server omitted a required EDNS response",
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
                    let lower = {
                        let mut states = self.states();
                        states
                            .entry(server)
                            .or_default()
                            .features
                            .record_do_off(level, Instant::now())
                    };
                    if feature_retries < MAX_FEATURE_RETRIES {
                        feature_retries += 1;
                        forced_level = Some(lower);
                        continue;
                    }
                    return edns::response_for_client(query, &response)
                        .map_err(ResolveError::from);
                }
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

            if prepared.managed_opt {
                let mut states = self.states();
                let features = &mut states.entry(server).or_default().features;
                if rcode_probe && !rcode_requests_feature_downgrade(rcode) {
                    features.downgrade_to(level, Instant::now());
                }
                features.record_success(level);
            }
            return edns::response_for_client(query, &response).map_err(ResolveError::from);
        }
    }

    fn record_bad_opt(&self, server: SocketAddr, level: FeatureLevel) -> FeatureLevel {
        let mut states = self.states();
        states
            .entry(server)
            .or_default()
            .features
            .record_bad_opt(level, Instant::now())
    }
}

fn rcode_requests_feature_downgrade(rcode: u16) -> bool {
    matches!(rcode, RCODE_FORMERR | RCODE_SERVFAIL | RCODE_NOTIMP)
}
