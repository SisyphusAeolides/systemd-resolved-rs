// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::cache::{Cache, CacheKey};
use crate::config::{Config, DnsServerSpec, Domain, SupportMode, TlsMode, ValidationMode};
use crate::edns::{self, FeatureLevel, ServerFeatureState};
use crate::hosts::Hosts;
use crate::native;
use crate::networkd::LinkState as NetworkdLinkState;
use crate::policy::{choose_server, update_rtt, ServerMetric};
use crate::routing::{LinkError, LinkState, RouteScope, RoutingTable, ScopeKind};
use crate::transport::{ServerTransportState, TransportMode, TRANSPORT_RETRY_ATTEMPTS};
use crate::wire::{
    self, extract_address_records, extract_ptr_names, first_question, local_response, make_query,
    make_query_with_class, response_matches, reverse_name, servfail_for, validate, Header,
    WireError, TYPE_A, TYPE_AAAA, TYPE_PTR,
};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread;
use std::time::{Duration, Instant};

const UDP_POOL_PER_SERVER_MAX: usize = 8;
const TCP_POOL_PER_SERVER_MAX: usize = 4;
const DNS_TRANSACTION_ATTEMPTS_MAX: usize = 24;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(120);
const DNS_TRANSACTION_UDP_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TRANSACTION_TCP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct DnsAttemptBudget {
    attempts: usize,
    deadline: Instant,
}

impl DnsAttemptBudget {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            attempts: 0,
            deadline: now.checked_add(DNS_QUERY_TIMEOUT).unwrap_or(now),
        }
    }

    fn remaining(&self) -> Result<Duration, ResolveError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out").into())
    }

    fn begin_attempt(&mut self) -> Result<Duration, ResolveError> {
        if self.exhausted() {
            return Err(ResolveError::Protocol(
                "maximum DNS transaction attempts reached",
            ));
        }
        let remaining = self.remaining()?;
        self.attempts += 1;
        Ok(remaining)
    }

    #[cfg(test)]
    const fn attempts(&self) -> usize {
        self.attempts
    }

    const fn exhausted(&self) -> bool {
        self.attempts >= DNS_TRANSACTION_ATTEMPTS_MAX
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryMode {
    Full,
    Proxy,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ServerKey {
    scope: i32,
    server: SocketAddr,
    slot: usize,
}

impl ServerKey {
    const fn new(scope: ScopeKind, server: SocketAddr) -> Self {
        Self::with_slot(scope, server, 0)
    }

    const fn with_slot(scope: ScopeKind, server: SocketAddr, slot: usize) -> Self {
        let scope = match scope {
            ScopeKind::Global => 0,
            ScopeKind::Fallback => -1,
            ScopeKind::Link(ifindex) => ifindex,
        };
        Self {
            scope,
            server,
            slot,
        }
    }

    const fn server(self) -> SocketAddr {
        self.server
    }

    const fn scope_kind(self) -> ScopeKind {
        if self.scope > 0 {
            ScopeKind::Link(self.scope)
        } else if self.scope < 0 {
            ScopeKind::Fallback
        } else {
            ScopeKind::Global
        }
    }

    const fn slot(self) -> usize {
        self.slot
    }

    const fn ifindex(self) -> Option<i32> {
        if self.scope > 0 {
            Some(self.scope)
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
struct ServerState {
    metric: ServerMetric,
    cooldown_until: Option<Instant>,
    features: ServerFeatureState,
    transport: ServerTransportState,
    missing_root_rrsig: bool,
}

#[derive(Debug, Default)]
struct Counters {
    transactions: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    failures: AtomicU64,
    local_answers: AtomicU64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct InflightKey {
    route: u64,
    query: Vec<u8>,
}

impl InflightKey {
    fn new(route: u64, query: &[u8]) -> Result<Self, WireError> {
        let mut query = query.to_vec();
        wire::rewrite_id(&mut query, 0)?;
        Ok(Self { route, query })
    }
}

#[derive(Debug, Default)]
struct InflightState {
    running: bool,
    response: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct InflightEntry {
    state: Mutex<InflightState>,
    ready: Condvar,
}

impl InflightEntry {
    fn wait(&self) -> Option<Vec<u8>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while state.running {
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        state.response.clone()
    }
}

#[derive(Debug, Default)]
struct Inflight {
    entries: Mutex<HashMap<InflightKey, Arc<InflightEntry>>>,
}

impl Inflight {
    fn begin(&self, key: InflightKey) -> InflightRole<'_> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = entries.get(&key) {
            return InflightRole::Follower(Arc::clone(entry));
        }

        let entry = Arc::new(InflightEntry {
            state: Mutex::new(InflightState {
                running: true,
                response: None,
            }),
            ready: Condvar::new(),
        });
        entries.insert(key.clone(), Arc::clone(&entry));
        InflightRole::Leader(InflightLeader {
            owner: self,
            key,
            entry,
            completed: false,
        })
    }

    fn finish(&self, key: &InflightKey, entry: &Arc<InflightEntry>, response: Option<Vec<u8>>) {
        {
            let mut state = entry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.response = response;
            state.running = false;
            entry.ready.notify_all();
        }

        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(key);
        }
    }
}

#[derive(Debug)]
enum InflightRole<'a> {
    Leader(InflightLeader<'a>),
    Follower(Arc<InflightEntry>),
}

#[derive(Debug)]
struct InflightLeader<'a> {
    owner: &'a Inflight,
    key: InflightKey,
    entry: Arc<InflightEntry>,
    completed: bool,
}

impl InflightLeader<'_> {
    fn complete(mut self, response: Option<Vec<u8>>) {
        self.owner.finish(&self.key, &self.entry, response);
        self.completed = true;
    }
}

impl Drop for InflightLeader<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.finish(&self.key, &self.entry, None);
        }
    }
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
    states: Mutex<HashMap<ServerKey, ServerState>>,
    udp_sockets: Mutex<HashMap<ServerKey, Vec<UdpSocket>>>,
    tcp_streams: Mutex<HashMap<ServerKey, Vec<TcpStream>>>,
    routing: RwLock<RoutingTable>,
    networkd_links: RwLock<HashMap<i32, NetworkdLinkState>>,
    link_server_specs: RwLock<HashMap<i32, Vec<DnsServerSpec>>>,
    routing_generation: AtomicU64,
    inflight: Inflight,
    cache: Cache,
    hosts: RwLock<Hosts>,
    next_id: AtomicU16,
    counters: Counters,
}
