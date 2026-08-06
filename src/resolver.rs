// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::cache::{Cache, CacheKey};
use crate::config::Config;
use crate::hosts::Hosts;
use crate::policy::{choose_server, update_rtt, ServerMetric};
use crate::wire::{
    self, extract_addresses, extract_ptr_names, first_question, local_response, make_query,
    response_matches, reverse_name, servfail_for, validate, Header, WireError, TYPE_A, TYPE_AAAA,
    TYPE_PTR,
};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryMode {
    Full,
    Proxy,
}

#[derive(Debug)]
struct ServerState {
    metric: ServerMetric,
    cooldown_until: Option<Instant>,
}

#[derive(Debug, Default)]
struct Counters {
    transactions: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    failures: AtomicU64,
    local_answers: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolverStats {
    pub transactions: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub failures: u64,
    pub local_answers: u64,
    pub cache_entries: usize,
}

#[derive(Debug)]
pub struct Resolver {
    config: Config,
    servers: Vec<SocketAddr>,
    states: Mutex<Vec<ServerState>>,
    cache: Cache,
    hosts: RwLock<Hosts>,
    next_id: AtomicU16,
    counters: Counters,
}

impl Resolver {
    pub fn new(config: Config) -> Self {
        let servers = config.effective_upstreams();
        let states = servers
            .iter()
            .map(|_| ServerState {
                metric: ServerMetric::default(),
                cooldown_until: None,
            })
            .collect();
        let hosts = if config.read_etc_hosts {
            Hosts::load(&config.hosts_path).unwrap_or_default()
        } else {
            Hosts::default()
        };
        Self {
            cache: Cache::new(
                config.cache_size,
                config.cache_max_ttl,
                config.stale_retention,
            ),
            config,
            servers,
            states: Mutex::new(states),
            hosts: RwLock::new(hosts),
            next_id: AtomicU16::new(1),
            counters: Counters::default(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn states(&self) -> MutexGuard<'_, Vec<ServerState>> {
        self.states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn hosts(&self) -> RwLockReadGuard<'_, Hosts> {
        self.hosts
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn hosts_mut(&self) -> RwLockWriteGuard<'_, Hosts> {
        self.hosts
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn transaction_id(&self) -> u16 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn query(&self, query: &[u8], mode: QueryMode) -> Result<Vec<u8>, ResolveError> {
        validate(query, false)?;
        let header = Header::parse(query)?;
        let question = first_question(query)?;
        self.counters.transactions.fetch_add(1, Ordering::Relaxed);

        if mode == QueryMode::Full && self.config.read_etc_hosts {
            if let Some(records) = self.hosts().lookup(&question) {
                self.counters.local_answers.fetch_add(1, Ordering::Relaxed);
                return Ok(local_response(query, &records, 0)?);
            }
        }

        let key = CacheKey {
            name: question.name.canonical_wire().to_vec(),
            rr_type: question.rr_type,
            class: question.class,
            checking_disabled: header.checking_disabled(),
        };
        if self.config.cache {
            if let Some(response) = self.cache.get(&key, header.id, false) {
                self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(response);
            }
            self.counters.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        if self.servers.is_empty() {
            self.counters.failures.fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::NoNameServers);
        }

        let mut attempted = HashSet::new();
        let mut last_error = None;
        for _ in 0..self.config.attempts {
            if attempted.len() == self.servers.len() {
                attempted.clear();
            }
            let Some(index) = self.select_server(&attempted) else {
                break;
            };
            attempted.insert(index);
            let started = Instant::now();
            match self.exchange(self.servers[index], query) {
                Ok(response) => {
                    self.record_success(index, started.elapsed());
                    if self.config.cache {
                        let _ = self.cache.insert(key.clone(), &response);
                    }
                    return Ok(response);
                }
                Err(error) => {
                    self.record_failure(index, started.elapsed());
                    last_error = Some(error);
                }
            }
        }

        if self.config.cache {
            if let Some(response) = self.cache.get(&key, header.id, true) {
                self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(response);
            }
        }
        self.counters.failures.fetch_add(1, Ordering::Relaxed);
        Err(last_error.unwrap_or(ResolveError::NoNameServers))
    }

    pub fn query_or_servfail(&self, query: &[u8], mode: QueryMode) -> Result<Vec<u8>, WireError> {
        match self.query(query, mode) {
            Ok(response) => Ok(response),
            Err(_) => servfail_for(query),
        }
    }

    fn select_server(&self, attempted: &HashSet<usize>) -> Option<usize> {
        let now = Instant::now();
        let states = self.states();
        let metrics: Vec<_> = states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let mut metric = state.metric;
                metric.cooldown_ms = state
                    .cooldown_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(duration_milliseconds)
                    .unwrap_or(0);
                if attempted.contains(&index) {
                    metric.cooldown_ms = i32::MAX;
                    metric.failures = i32::MAX / 1000;
                }
                metric
            })
            .collect();
        choose_server(&metrics)
    }

    fn record_success(&self, index: usize, duration: Duration) {
        let mut states = self.states();
        let state = &mut states[index];
        state.metric.round_trip_ms = update_rtt(
            state.metric.round_trip_ms,
            duration.as_secs_f64() * 1000.0,
            true,
        );
        state.metric.failures = 0;
        state.cooldown_until = None;
    }

    fn record_failure(&self, index: usize, duration: Duration) {
        let mut states = self.states();
        let state = &mut states[index];
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

    fn exchange(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolveError> {
        let bind_address = if server.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind_address)?;
        socket.set_read_timeout(Some(self.config.query_timeout))?;
        socket.set_write_timeout(Some(self.config.query_timeout))?;
        socket.connect(server)?;
        if socket.send(query)? != query.len() {
            return Err(ResolveError::Protocol("short UDP send"));
        }
        let mut response = vec![0; usize::from(u16::MAX)];
        let length = socket.recv(&mut response)?;
        response.truncate(length);
        response_matches(query, &response)?;
        if Header::parse(&response)?.truncated() {
            self.exchange_tcp(server, query)
        } else {
            Ok(response)
        }
    }

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolveError> {
        let length = u16::try_from(query.len())
            .map_err(|_| ResolveError::Protocol("DNS query exceeds the TCP frame limit"))?;
        let mut stream = TcpStream::connect_timeout(&server, self.config.query_timeout)?;
        stream.set_read_timeout(Some(self.config.query_timeout))?;
        stream.set_write_timeout(Some(self.config.query_timeout))?;
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(query)?;

        let mut length = [0; 2];
        stream.read_exact(&mut length)?;
        let length = usize::from(u16::from_be_bytes(length));
        if length < wire::DNS_HEADER_LEN {
            return Err(ResolveError::Protocol("short DNS-over-TCP frame"));
        }
        let mut response = vec![0; length];
        stream.read_exact(&mut response)?;
        response_matches(query, &response)?;
        Ok(response)
    }

    pub fn lookup_name(&self, name: &str, family: i32) -> Result<NameLookup, ResolveError> {
        let types: &[u16] = match family {
            0 => &[TYPE_A, TYPE_AAAA],
            2 => &[TYPE_A],
            10 => &[TYPE_AAAA],
            _ => return Err(ResolveError::UnsupportedFamily(family)),
        };
        let mut addresses = Vec::new();
        let mut last_error = None;
        for &rr_type in types {
            let query = make_query(name, rr_type, self.transaction_id())?;
            match self.query(&query, QueryMode::Full) {
                Ok(response) => {
                    for address in
                        extract_addresses(&response, Some(family).filter(|value| *value != 0))?
                    {
                        if !addresses.contains(&address) {
                            addresses.push(address);
                        }
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }
        if addresses.is_empty() {
            return Err(last_error.unwrap_or(ResolveError::NoSuchResourceRecord));
        }
        Ok(NameLookup {
            addresses,
            canonical_name: name.trim_end_matches('.').to_owned(),
            flags: 0,
        })
    }

    pub fn lookup_address(&self, address: IpAddr) -> Result<AddressLookup, ResolveError> {
        let query = make_query(&reverse_name(address), TYPE_PTR, self.transaction_id())?;
        let names = extract_ptr_names(&self.query(&query, QueryMode::Full)?)?;
        if names.is_empty() {
            Err(ResolveError::NoSuchResourceRecord)
        } else {
            Ok(AddressLookup { names, flags: 0 })
        }
    }

    pub fn resolve_record(&self, name: &str, rr_type: u16) -> Result<Vec<u8>, ResolveError> {
        let query = make_query(name, rr_type, self.transaction_id())?;
        self.query(&query, QueryMode::Full)
    }

    pub fn reload_hosts(&self) -> io::Result<()> {
        let hosts = if self.config.read_etc_hosts {
            Hosts::load(&self.config.hosts_path)?
        } else {
            Hosts::default()
        };
        *self.hosts_mut() = hosts;
        Ok(())
    }

    pub fn flush_cache(&self) {
        self.cache.flush();
    }

    pub fn reset_server_features(&self) {
        for state in self.states().iter_mut() {
            state.metric = ServerMetric::default();
            state.cooldown_until = None;
        }
    }

    pub fn reset_statistics(&self) {
        self.counters.transactions.store(0, Ordering::Relaxed);
        self.counters.cache_hits.store(0, Ordering::Relaxed);
        self.counters.cache_misses.store(0, Ordering::Relaxed);
        self.counters.failures.store(0, Ordering::Relaxed);
        self.counters.local_answers.store(0, Ordering::Relaxed);
    }

    pub fn stats(&self) -> ResolverStats {
        ResolverStats {
            transactions: self.counters.transactions.load(Ordering::Relaxed),
            cache_hits: self.counters.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.counters.cache_misses.load(Ordering::Relaxed),
            failures: self.counters.failures.load(Ordering::Relaxed),
            local_answers: self.counters.local_answers.load(Ordering::Relaxed),
            cache_entries: self.cache.len(),
        }
    }
}

fn duration_milliseconds(duration: Duration) -> i32 {
    i32::try_from(duration.as_millis()).unwrap_or(i32::MAX)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameLookup {
    pub addresses: Vec<IpAddr>,
    pub canonical_name: String,
    pub flags: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressLookup {
    pub names: Vec<String>,
    pub flags: u64,
}

#[derive(Debug)]
pub enum ResolveError {
    Io(io::Error),
    Wire(WireError),
    NoNameServers,
    NoSuchResourceRecord,
    UnsupportedFamily(i32),
    Protocol(&'static str),
}

impl ResolveError {
    pub fn varlink_id(&self) -> &'static str {
        match self {
            Self::NoNameServers => "io.systemd.Resolve.NoNameServers",
            Self::NoSuchResourceRecord => "io.systemd.Resolve.NoSuchResourceRecord",
            Self::UnsupportedFamily(_) => "io.systemd.Resolve.BadAddressSize",
            Self::Io(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                "io.systemd.Resolve.QueryTimedOut"
            }
            _ => "io.systemd.Resolve.MaxAttemptsReached",
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::NoNameServers => formatter.write_str("no DNS name servers are configured"),
            Self::NoSuchResourceRecord => formatter.write_str("no such DNS resource record"),
            Self::UnsupportedFamily(family) => {
                write!(formatter, "unsupported address family {family}")
            }
            Self::Protocol(message) => write!(formatter, "DNS protocol error: {message}"),
        }
    }
}

impl Error for ResolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ResolveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<WireError> for ResolveError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_is_answered_without_an_upstream() {
        let mut config = Config::default();
        config.upstreams.clear();
        config.fallback_upstreams.clear();
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_A, 55).expect("query");
        let response = resolver
            .query(&query, QueryMode::Full)
            .expect("local response");
        assert_eq!(
            extract_addresses(&response, Some(2)).expect("address"),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    #[test]
    fn proxy_mode_bypasses_local_synthesis() {
        let mut config = Config::default();
        config.upstreams.clear();
        config.fallback_upstreams.clear();
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_A, 55).expect("query");
        assert!(matches!(
            resolver.query(&query, QueryMode::Proxy),
            Err(ResolveError::NoNameServers)
        ));
    }
}
