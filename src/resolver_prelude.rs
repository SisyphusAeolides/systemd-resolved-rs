// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::cache::{Cache, CacheKey};
use crate::config::{Config, Domain, SupportMode, TlsMode, ValidationMode};
use crate::edns::{self, FeatureLevel, ServerFeatureState};
use crate::hosts::Hosts;
use crate::native;
use crate::policy::{choose_server, update_rtt, ServerMetric};
use crate::routing::{LinkError, LinkState, RouteScope, RoutingTable};
use crate::transport::{
    ServerTransportState, TransportMode, TRANSPORT_RETRY_ATTEMPTS,
};
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
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};
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
    states: Mutex<HashMap<SocketAddr, ServerState>>,
    routing: RwLock<RoutingTable>,
    routing_generation: AtomicU64,
    inflight: Inflight,
    cache: Cache,
    hosts: RwLock<Hosts>,
    next_id: AtomicU16,
    counters: Counters,
}
