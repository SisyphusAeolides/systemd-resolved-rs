// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::cache::{Cache, CacheKey};
use crate::config::{Config, Domain, SupportMode, TlsMode, ValidationMode};
use crate::hosts::Hosts;
use crate::policy::{choose_server, update_rtt, ServerMetric};
use crate::routing::{LinkError, LinkState, RouteScope, RoutingTable};
use crate::wire::{
    self, extract_address_records, extract_ptr_names, first_question, local_response, make_query,
    make_query_with_class, response_matches, reverse_name, servfail_for, validate, Header,
    WireError, TYPE_A, TYPE_AAAA, TYPE_PTR,
};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryMode {
    Full,
    Proxy,
}

#[derive(Debug, Default)]
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
    global_servers: Vec<SocketAddr>,
    fallback_servers: Vec<SocketAddr>,
    states: Mutex<HashMap<SocketAddr, ServerState>>,
    routing: RwLock<RoutingTable>,
    routing_generation: AtomicU64,
    cache: Cache,
    hosts: RwLock<Hosts>,
    next_id: AtomicU16,
    counters: Counters,
}

impl Resolver {
    pub fn new(config: Config) -> Self {
        let global_servers = config.configured_upstreams();
        let fallback_servers = config.configured_fallback_upstreams();
        let mut states = HashMap::new();
        for server in global_servers.iter().chain(fallback_servers.iter()) {
            states.entry(*server).or_default();
        }
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
            global_servers,
            fallback_servers,
            states: Mutex::new(states),
            routing: RwLock::new(RoutingTable::default()),
            routing_generation: AtomicU64::new(1),
            hosts: RwLock::new(hosts),
            next_id: AtomicU16::new(1),
            counters: Counters::default(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn states(&self) -> MutexGuard<'_, HashMap<SocketAddr, ServerState>> {
        self.states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn routing(&self) -> RwLockReadGuard<'_, RoutingTable> {
        self.routing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn routing_mut(&self) -> RwLockWriteGuard<'_, RoutingTable> {
        self.routing
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn links(&self) -> Vec<LinkState> {
        self.routing().links()
    }

    pub fn link(&self, ifindex: i32) -> Option<LinkState> {
        self.routing().link(ifindex)
    }

    pub fn set_link_dns(&self, ifindex: i32, servers: Vec<SocketAddr>) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_dns(ifindex, servers)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_domains(&self, ifindex: i32, domains: Vec<Domain>) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_domains(ifindex, domains)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_default_route(
        &self,
        ifindex: i32,
        default_route: Option<bool>,
    ) -> Result<(), LinkError> {
        let changed = self
            .routing_mut()
            .set_default_route(ifindex, default_route)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_llmnr(&self, ifindex: i32, mode: SupportMode) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_llmnr(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_multicast_dns(&self, ifindex: i32, mode: SupportMode) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_multicast_dns(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dns_over_tls(&self, ifindex: i32, mode: TlsMode) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_dns_over_tls(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dnssec(&self, ifindex: i32, mode: ValidationMode) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_dnssec(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dnssec_negative_trust_anchors(
        &self,
        ifindex: i32,
        anchors: Vec<String>,
    ) -> Result<(), LinkError> {
        let changed = self
            .routing_mut()
            .set_dnssec_negative_trust_anchors(ifindex, anchors)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn revert_link(&self, ifindex: i32) -> Result<(), LinkError> {
        let changed = self.routing_mut().revert(ifindex)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    fn finish_routing_change(&self, changed: bool) {
        if changed {
            self.routing_generation.fetch_add(1, Ordering::AcqRel);
            self.cache.flush();
        }
    }

    fn search_domains(&self, ifindex: Option<i32>) -> Result<Vec<Domain>, ResolveError> {
        Ok(self
            .routing()
            .search_domains(&self.config.domains, ifindex)?)
    }

    fn hosts(&self) -> RwLockReadGuard<'_, Hosts> {
        self.hosts
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn hosts_mut(&self) -> RwLockWriteGuard<'_, Hosts> {
        self.hosts
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn transaction_id(&self) -> u16 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn query(&self, query: &[u8], mode: QueryMode) -> Result<Vec<u8>, ResolveError> {
        self.query_on_link(query, mode, None)
    }

    pub fn query_on_link(
        &self,
        query: &[u8],
        mode: QueryMode,
        ifindex: Option<i32>,
    ) -> Result<Vec<u8>, ResolveError> {
        validate(query, false)?;
        let header = Header::parse(query)?;
        let question = first_question(query)?;
        if let Some(ifindex) = ifindex.filter(|value| *value < 0) {
            return Err(LinkError::InvalidIfindex(ifindex).into());
        }
        self.counters.transactions.fetch_add(1, Ordering::Relaxed);

        if mode == QueryMode::Full {
            if let Some(records) = self.hosts().lookup(&question) {
                self.counters.local_answers.fetch_add(1, Ordering::Relaxed);
                return Ok(local_response(query, &records, 0)?);
            }
        }

        let route_generation = self.routing_generation.load(Ordering::Acquire);
        let route = route_cache_id(route_generation, ifindex);
        let key = CacheKey {
            name: question.name.canonical_wire().to_vec(),
            rr_type: question.rr_type,
            class: question.class,
            checking_disabled: header.checking_disabled(),
            route,
        };
        if self.config.cache {
            if let Some(response) = self.cache.get(&key, header.id, false) {
                self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(response);
            }
            self.counters.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        let scopes = self.routing().select(
            question.name.text(),
            ifindex,
            &self.global_servers,
            &self.fallback_servers,
            &self.config.domains,
        )?;
        if scopes.is_empty() {
            self.counters.failures.fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::NoNameServers);
        }

        match self.query_scopes(&scopes, query) {
            Ok(response) => {
                if self.config.cache {
                    let _ = self.cache.insert(key, &response);
                }
                Ok(response)
            }
            Err(error) => {
                if self.config.cache {
                    if let Some(response) = self.cache.get(&key, header.id, true) {
                        self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                        return Ok(response);
                    }
                }
                self.counters.failures.fetch_add(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    pub fn query_or_servfail(&self, query: &[u8], mode: QueryMode) -> Result<Vec<u8>, WireError> {
        match self.query(query, mode) {
            Ok(response) => Ok(response),
            Err(_) => servfail_for(query),
        }
    }

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
        let mut attempted = HashSet::new();
        let mut last_error = None;
        for _ in 0..self.config.attempts {
            if attempted.len() == servers.len() {
                attempted.clear();
            }
            let Some(server) = self.select_server(servers, &attempted) else {
                break;
            };
            attempted.insert(server);
            let started = Instant::now();
            match self.exchange(server, query) {
                Ok(response) => {
                    self.record_success(server, started.elapsed());
                    return Ok(response);
                }
                Err(error) => {
                    self.record_failure(server, started.elapsed());
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or(ResolveError::NoNameServers))
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
        self.lookup_name_on_link(name, family, None)
    }

    pub fn lookup_name_on_link(
        &self,
        name: &str,
        family: i32,
        ifindex: Option<i32>,
    ) -> Result<NameLookup, ResolveError> {
        let types: &[u16] = match family {
            0 => &[TYPE_A, TYPE_AAAA],
            2 => &[TYPE_A],
            10 => &[TYPE_AAAA],
            _ => return Err(ResolveError::UnsupportedFamily(family)),
        };
        if self.has_local_name(name, types)? {
            return self.lookup_name_exact(name, types, ifindex);
        }

        let domains = self.search_domains(ifindex)?;
        let candidates =
            lookup_candidates(name, &domains, self.config.resolve_unicast_single_label);
        let mut last_error = None;
        for candidate in candidates {
            match self.lookup_name_exact(&candidate, types, ifindex) {
                Ok(result) => return Ok(result),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(ResolveError::NoSuchResourceRecord))
    }

    fn has_local_name(&self, name: &str, types: &[u16]) -> Result<bool, ResolveError> {
        let hosts = self.hosts();
        for &rr_type in types {
            let query = make_query(name, rr_type, 0)?;
            let question = first_question(&query)?;
            if hosts.lookup(&question).is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn lookup_name_exact(
        &self,
        name: &str,
        types: &[u16],
        ifindex: Option<i32>,
    ) -> Result<NameLookup, ResolveError> {
        let mut addresses = Vec::new();
        let mut canonical_name = None;
        let mut last_error = None;
        for &rr_type in types {
            let query = make_query(name, rr_type, self.transaction_id())?;
            match self.query_on_link(&query, QueryMode::Full, ifindex) {
                Ok(response) => {
                    let response_family = match rr_type {
                        TYPE_A => Some(2),
                        TYPE_AAAA => Some(10),
                        _ => None,
                    };
                    let records = extract_address_records(&response, response_family)?;
                    if !records.addresses.is_empty() && canonical_name.is_none() {
                        canonical_name = Some(records.canonical_name);
                    }
                    for address in records.addresses {
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
            canonical_name: canonical_name.unwrap_or_else(|| name.trim_end_matches('.').to_owned()),
            flags: 0,
        })
    }

    pub fn lookup_address(&self, address: IpAddr) -> Result<AddressLookup, ResolveError> {
        self.lookup_address_on_link(address, None)
    }

    pub fn lookup_address_on_link(
        &self,
        address: IpAddr,
        ifindex: Option<i32>,
    ) -> Result<AddressLookup, ResolveError> {
        let query = make_query(&reverse_name(address), TYPE_PTR, self.transaction_id())?;
        let names = extract_ptr_names(&self.query_on_link(&query, QueryMode::Full, ifindex)?)?;
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
        let query = make_query_with_class(name, rr_type, class, self.transaction_id())?;
        self.query_on_link(&query, QueryMode::Full, ifindex)
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
        for state in self.states().values_mut() {
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

fn lookup_candidates(
    name: &str,
    domains: &[Domain],
    resolve_unicast_single_label: bool,
) -> Vec<String> {
    let relative = name.trim_end_matches('.');
    if relative.is_empty() || name.ends_with('.') || relative.contains('.') {
        return vec![name.to_owned()];
    }

    let mut candidates = Vec::new();
    for domain in domains {
        if domain.route_only || domain.name == "." {
            continue;
        }
        let candidate = format!("{relative}.{}", domain.name);
        if !candidates
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(&candidate))
        {
            candidates.push(candidate);
        }
    }
    if resolve_unicast_single_label
        && !candidates
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(relative))
    {
        candidates.push(relative.to_owned());
    }
    candidates
}

fn response_is_success(response: &[u8]) -> bool {
    matches!(Header::parse(response), Ok(header) if header.response_code() == 0)
}

fn route_cache_id(generation: u64, ifindex: Option<i32>) -> u64 {
    let ifindex = ifindex
        .and_then(|value| u32::try_from(value).ok())
        .map_or(0, u64::from);
    generation.rotate_left(32) ^ ifindex
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
    Link(LinkError),
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
            Self::Link(LinkError::NoSuchLink(_)) => "io.systemd.Resolve.NoSuchLink",
            Self::Link(_) => "io.systemd.Resolve.InvalidParameter",
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
            Self::Link(error) => write!(formatter, "{error}"),
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
            Self::Link(error) => Some(error),
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

impl From<LinkError> for ResolveError {
    fn from(error: LinkError) -> Self {
        Self::Link(error)
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
            wire::extract_addresses(&response, Some(2)).expect("address"),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    #[test]
    fn lookup_name_follows_cname_and_ignores_unrelated_addresses() {
        use crate::wire::{encode_name, question_end, TYPE_CNAME};
        use std::thread;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = socket.recv_from(&mut buffer).expect("receive query");
            let query = &buffer[..length];
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&3u16.to_be_bytes());
            response[8..12].fill(0);

            let canonical = encode_name("real.example.test").expect("canonical name");
            append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_CNAME, &canonical);
            append_test_answer(
                &mut response,
                &encode_name("unrelated.example.test").expect("unrelated owner"),
                TYPE_A,
                &[203, 0, 113, 9],
            );
            append_test_answer(&mut response, &canonical, TYPE_A, &[192, 0, 2, 42]);
            socket.send_to(&response, peer).expect("send DNS response");
        });

        let config = Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let lookup = Resolver::new(config)
            .lookup_name("alias.example.test", 2)
            .expect("CNAME lookup");
        worker.join().expect("test DNS worker");

        assert_eq!(lookup.canonical_name, "real.example.test");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))]
        );
    }

    fn append_test_answer(packet: &mut Vec<u8>, owner: &[u8], rr_type: u16, rdata: &[u8]) {
        packet.extend_from_slice(owner);
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("test RDATA length")
                .to_be_bytes(),
        );
        packet.extend_from_slice(rdata);
    }

    #[test]
    fn synthetic_answers_do_not_depend_on_reading_etc_hosts() {
        let config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            read_etc_hosts: false,
            ..Config::default()
        };
        let lookup = Resolver::new(config)
            .lookup_name("localhost", 2)
            .expect("synthetic lookup");
        assert_eq!(lookup.addresses, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn candidate_expansion_skips_route_only_domains() {
        let domains = vec![
            Domain {
                name: "route.test".to_owned(),
                route_only: true,
            },
            Domain {
                name: "example.test".to_owned(),
                route_only: false,
            },
            Domain {
                name: "lab.test".to_owned(),
                route_only: false,
            },
        ];
        assert_eq!(
            lookup_candidates("host", &domains, false),
            vec!["host.example.test".to_owned(), "host.lab.test".to_owned()]
        );
        assert_eq!(
            lookup_candidates("host", &domains, true),
            vec![
                "host.example.test".to_owned(),
                "host.lab.test".to_owned(),
                "host".to_owned(),
            ]
        );
        assert!(lookup_candidates("host", &[], false).is_empty());
        assert_eq!(
            lookup_candidates("host.example", &domains, false),
            vec!["host.example".to_owned()]
        );
        assert_eq!(
            lookup_candidates("host.", &domains, false),
            vec!["host.".to_owned()]
        );
    }

    #[test]
    fn lookup_name_tries_search_domains_in_order() {
        use crate::wire::question_end;
        use std::thread;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            for (index, expected_name) in ["host.example.test", "host.lab.test"]
                .into_iter()
                .enumerate()
            {
                let (length, peer) = socket.recv_from(&mut buffer).expect("receive query");
                let query = &buffer[..length];
                let question = first_question(query).expect("question");
                assert_eq!(question.name.text(), expected_name);
                let end = question_end(query).expect("question end");
                let mut response = query[..end].to_vec();
                let flags = if index == 0 { 0x8183u16 } else { 0x8180u16 };
                response[2..4].copy_from_slice(&flags.to_be_bytes());
                response[6..12].fill(0);
                if index == 1 {
                    response[6..8].copy_from_slice(&1u16.to_be_bytes());
                    append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_A, &[192, 0, 2, 77]);
                }
                socket.send_to(&response, peer).expect("send DNS response");
            }
        });

        let config = Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            domains: vec![
                Domain {
                    name: "route.test".to_owned(),
                    route_only: true,
                },
                Domain {
                    name: "example.test".to_owned(),
                    route_only: false,
                },
                Domain {
                    name: "lab.test".to_owned(),
                    route_only: false,
                },
            ],
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            resolve_unicast_single_label: false,
            ..Config::default()
        };
        let lookup = Resolver::new(config)
            .lookup_name("host", 2)
            .expect("search-domain lookup");
        worker.join().expect("test DNS worker");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77))]
        );
        assert_eq!(lookup.canonical_name, "host.lab.test");
    }

    #[test]
    fn longest_suffix_routes_to_the_matching_link() {
        use crate::wire::question_end;
        use std::thread;

        let global = UdpSocket::bind("127.0.0.1:0").expect("bind global DNS server");
        global
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set global timeout");
        let link = UdpSocket::bind("127.0.0.1:0").expect("bind link DNS server");
        link.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set link timeout");
        let link_address = link.local_addr().expect("link DNS address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = link.recv_from(&mut buffer).expect("receive link query");
            let query = &buffer[..length];
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response[8..12].fill(0);
            append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_A, &[192, 0, 2, 88]);
            link.send_to(&response, peer).expect("send link response");
        });

        let config = Config {
            upstreams: vec![global.local_addr().expect("global DNS address")],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        resolver
            .set_link_dns(7, vec![link_address])
            .expect("set link DNS");
        resolver
            .set_link_domains(
                7,
                vec![Domain {
                    name: "corp.example".to_owned(),
                    route_only: true,
                }],
            )
            .expect("set link domain");

        let lookup = resolver
            .lookup_name("host.corp.example", 2)
            .expect("split DNS lookup");
        worker.join().expect("link DNS worker");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 88))]
        );
        let mut buffer = [0; 512];
        assert!(global.recv_from(&mut buffer).is_err());
    }

    #[test]
    fn equal_best_scopes_prefer_a_successful_response() {
        use crate::wire::question_end;
        use std::thread;

        let negative = UdpSocket::bind("127.0.0.1:0").expect("bind negative DNS server");
        let negative_address = negative.local_addr().expect("negative DNS address");
        let positive = UdpSocket::bind("127.0.0.1:0").expect("bind positive DNS server");
        let positive_address = positive.local_addr().expect("positive DNS address");

        let negative_worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = negative
                .recv_from(&mut buffer)
                .expect("receive negative query");
            let query = &buffer[..length];
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8183u16.to_be_bytes());
            response[6..12].fill(0);
            negative
                .send_to(&response, peer)
                .expect("send negative response");
        });
        let positive_worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = positive
                .recv_from(&mut buffer)
                .expect("receive positive query");
            let query = &buffer[..length];
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response[8..12].fill(0);
            append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_A, &[192, 0, 2, 99]);
            positive
                .send_to(&response, peer)
                .expect("send positive response");
        });

        let config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        for (ifindex, server) in [(7, negative_address), (8, positive_address)] {
            resolver
                .set_link_dns(ifindex, vec![server])
                .expect("set link DNS");
            resolver
                .set_link_domains(
                    ifindex,
                    vec![Domain {
                        name: "corp.example".to_owned(),
                        route_only: true,
                    }],
                )
                .expect("set link domain");
        }

        let lookup = resolver
            .lookup_name("host.corp.example", 2)
            .expect("parallel split DNS lookup");
        negative_worker.join().expect("negative DNS worker");
        positive_worker.join().expect("positive DNS worker");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))]
        );
    }

    #[test]
    fn per_link_search_domains_are_available_to_name_expansion() {
        let resolver = Resolver::new(Config::default());
        resolver
            .set_link_domains(
                9,
                vec![
                    Domain {
                        name: "search.example".to_owned(),
                        route_only: false,
                    },
                    Domain {
                        name: "route.example".to_owned(),
                        route_only: true,
                    },
                ],
            )
            .expect("set link domains");
        assert_eq!(
            resolver.search_domains(None).expect("search domains"),
            vec![Domain {
                name: "search.example".to_owned(),
                route_only: false,
            }]
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
