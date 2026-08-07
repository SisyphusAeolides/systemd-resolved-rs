const RCODE_REFUSED: u16 = 5;

impl Resolver {
    fn query_scopes(&self, scopes: &[RouteScope], query: &[u8]) -> Result<Vec<u8>, ResolveError> {
        if scopes.len() == 1 {
            return self.query_servers(&scopes[0].servers, query);
        }

        thread::scope(|thread_scope| {
            let (sender, receiver) = mpsc::channel();
            for route_scope in scopes {
                let sender = sender.clone();
                thread_scope.spawn(move || {
                    let _ = sender.send(self.query_servers(&route_scope.servers, query));
                });
            }
            drop(sender);

            let mut first_success = None;
            let mut last_response = None;
            let mut last_error = None;
            for result in receiver {
                match result {
                    Ok(response) if response_is_success(&response) => {
                        if first_success.is_none() {
                            first_success = Some(response);
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

    fn query_servers(&self, servers: &[SocketAddr], query: &[u8]) -> Result<Vec<u8>, ResolveError> {
        if servers.is_empty() {
            return Err(ResolveError::NoNameServers);
        }
        let mut budget = DnsAttemptBudget::new();
        let mut attempted = HashSet::new();
        let mut last_response = None;
        let mut last_error = None;
        for _ in 0..self.config.attempts {
            if budget.exhausted() || budget.expired() {
                break;
            }
            if attempted.len() == servers.len() {
                attempted.clear();
            }
            let Some(server) = self.select_server(servers, &attempted) else {
                break;
            };
            attempted.insert(server);
            let started = Instant::now();
            match self.exchange_with_features(server, query, &mut budget) {
                Ok(response) => {
                    self.record_success(server, started.elapsed());
                    if Header::parse(&response)?.response_code() == RCODE_REFUSED {
                        last_response = Some(response);
                        if attempted.len() == servers.len() {
                            break;
                        }
                        continue;
                    }
                    return Ok(response);
                }
                Err(error) => {
                    self.record_failure(server, started.elapsed());
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
        } else if budget.exhausted() && last_error.is_none() {
            Err(ResolveError::Protocol(
                "maximum DNS transaction attempts reached",
            ))
        } else {
            Err(last_error.unwrap_or(ResolveError::NoNameServers))
        }
    }

    fn select_server(
        &self,
        servers: &[SocketAddr],
        attempted: &HashSet<SocketAddr>,
    ) -> Option<SocketAddr> {
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

    fn record_success(&self, server: SocketAddr, duration: Duration) {
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

    fn record_failure(&self, server: SocketAddr, duration: Duration) {
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
