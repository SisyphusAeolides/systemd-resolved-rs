const RCODE_REFUSED: u16 = 5;

impl Resolver {
    fn query_scopes(
        &self,
        scopes: &[RouteScope],
        query: &[u8],
    ) -> Result<(Vec<u8>, SocketAddr), ResolveError> {
        if scopes.len() == 1 {
            return self.query_servers(scopes[0].kind, &scopes[0].servers, query);
        }

        thread::scope(|thread_scope| {
            let (sender, receiver) = mpsc::channel();
            for route_scope in scopes {
                let sender = sender.clone();
                thread_scope.spawn(move || {
                    let _ = sender.send(self.query_servers(
                        route_scope.kind,
                        &route_scope.servers,
                        query,
                    ));
                });
            }
            drop(sender);

            let mut first_success = None;
            let mut last_response = None;
            let mut last_error = None;
            for result in receiver {
                match result {
                    Ok((response, server)) if response_is_success(&response) => {
                        if first_success.is_none() {
                            first_success = Some((response, server));
                        }
                    }
                    Ok(response) => last_response = Some(response),
                    Err(error) => last_error = Some(error),
                }
            }
            if let Some(response) = first_success.or(last_response) {
                Ok(response)
            } else {
                Err(last_error.unwrap_or(ResolveError::NoNameServers))
            }
        })
    }

    fn query_servers(
        &self,
        scope: ScopeKind,
        servers: &[SocketAddr],
        query: &[u8],
    ) -> Result<(Vec<u8>, SocketAddr), ResolveError> {
        let server_specs = self.server_specs_for_scope(scope, servers);
        if server_specs.is_empty() {
            return Err(ResolveError::NoNameServers);
        }
        let server_keys = server_keys_for_specs(scope, &server_specs);
        let mut budget = DnsAttemptBudget::new();
        let mut attempted = HashSet::new();
        let mut last_response = None;
        let mut last_error = None;
        for _ in 0..self.config.attempts {
            if budget.exhausted() || budget.expired() {
                break;
            }
            if attempted.len() == server_keys.len() {
                attempted.clear();
            }
            let Some(server_key) = self.select_server(&server_keys, &attempted) else {
                break;
            };
            let server = server_key.server();
            attempted.insert(server_key);
            let started = Instant::now();
            match self.exchange_with_features(server_key, query, &mut budget) {
                Ok(response) => {
                    self.record_success(server_key, started.elapsed());
                    if Header::parse(&response)?.response_code() == RCODE_REFUSED {
                        last_response = Some((response, server));
                        if attempted.len() == server_keys.len() {
                            break;
                        }
                        continue;
                    }
                    return Ok((response, server));
                }
                Err(error) => {
                    self.record_failure(server_key, started.elapsed());
                    last_error = Some(error);
                    if budget.exhausted() || budget.expired() {
                        break;
                    }
                }
            }
        }
        if let Some(response) = last_response {
            Ok(response)
        } else if budget.expired() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out").into())
        } else if budget.exhausted() {
            Err(ResolveError::Protocol(
                "maximum DNS transaction attempts reached",
            ))
        } else {
            Err(last_error.unwrap_or(ResolveError::NoNameServers))
        }
    }

    fn server_specs_for_scope(
        &self,
        scope: ScopeKind,
        servers: &[SocketAddr],
    ) -> Vec<crate::config::DnsServerSpec> {
        let configured = match scope {
            ScopeKind::Global => self.config.configured_upstream_specs(),
            ScopeKind::Fallback => self.config.configured_fallback_upstream_specs(),
            ScopeKind::Link(_) => Vec::new(),
        };
        let mut output = Vec::new();
        for &address in servers {
            let before = output.len();
            for spec in configured.iter().filter(|spec| spec.address == address) {
                if !output.contains(spec) {
                    output.push(spec.clone());
                }
            }
            if output.len() == before {
                output.push(crate::config::DnsServerSpec {
                    address,
                    interface: None,
                    server_name: None,
                });
            }
        }
        output
    }

    fn select_server(
        &self,
        servers: &[ServerKey],
        attempted: &HashSet<ServerKey>,
    ) -> Option<ServerKey> {
        let now = Instant::now();
        let mut states = self.states();
        let metrics: Vec<_> = servers
            .iter()
            .map(|server| {
                let state = states.entry(*server).or_default();
                let mut metric = state.metric;
                metric.cooldown_ms = state
                    .cooldown_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map_or(0, duration_milliseconds);
                if attempted.contains(server) {
                    metric.cooldown_ms = i32::MAX;
                    metric.failures = i32::MAX / 1000;
                }
                metric
            })
            .collect();
        choose_server(&metrics).map(|index| servers[index])
    }

    fn record_success(&self, server: ServerKey, duration: Duration) {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        state.metric.round_trip_ms = update_rtt(
            state.metric.round_trip_ms,
            duration.as_secs_f64() * 1000.0,
            true,
        );
        state.metric.failures = 0;
        state.cooldown_until = None;
    }

    fn record_failure(&self, server: ServerKey, duration: Duration) {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        state.metric.round_trip_ms = update_rtt(
            state.metric.round_trip_ms,
            duration.as_secs_f64() * 1000.0,
            false,
        );
        state.metric.failures = state.metric.failures.saturating_add(1);
        let exponent = u32::try_from(state.metric.failures.clamp(0, 8)).unwrap_or(8);
        let delay = 250u64.saturating_mul(1u64 << exponent).min(60_000);
        state.cooldown_until = Instant::now().checked_add(Duration::from_millis(delay));
    }
}

fn server_keys_for_specs(
    scope: ScopeKind,
    specs: &[crate::config::DnsServerSpec],
) -> Vec<ServerKey> {
    let mut slots = HashMap::<SocketAddr, usize>::new();
    specs
        .iter()
        .map(|spec| {
            let slot = slots.entry(spec.address).or_insert(0);
            let key = ServerKey::with_slot(scope, spec.address, *slot);
            *slot += 1;
            key
        })
        .collect()
}
