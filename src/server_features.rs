//! Per-upstream feature memory (EDNS, DO, DoT, TCP-required).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

#[derive(Clone, Debug, Default)]
pub struct ServerFeatures {
    pub edns: Option<bool>,
    pub do_bit_ok: Option<bool>,
    pub udp_payload: u16,
    pub tcp_required: bool,
    pub dot_ok: Option<bool>,
    pub cookie_ok: Option<bool>,
    pub last_probe: Option<Instant>,
    pub consecutive_failures: u32,
}

impl ServerFeatures {
    pub fn fresh() -> Self {
        Self {
            udp_payload: 1232,
            ..Default::default()
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct ServerId {
    pub addr: SocketAddr,
    pub ifindex: i32,
    pub sni: Option<String>,
}

#[derive(Debug)]
pub struct FeatureTable {
    map: Mutex<HashMap<ServerId, ServerFeatures>>,
}

impl FeatureTable {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, id: &ServerId) -> ServerFeatures {
        self.map
            .lock()
            .get(id)
            .cloned()
            .unwrap_or_else(ServerFeatures::fresh)
    }

    pub fn set(&self, id: ServerId, f: ServerFeatures) {
        self.map.lock().insert(id, f);
    }

    pub fn reset_all(&self) {
        self.map.lock().clear();
    }

    pub fn mark_fail(&self, id: &ServerId) {
        let mut g = self.map.lock();
        let e = g.entry(id.clone()).or_insert_with(ServerFeatures::fresh);
        e.consecutive_failures = e.consecutive_failures.saturating_add(1);
        if e.consecutive_failures >= 3 {
            e.tcp_required = true;
        }
    }

    pub fn mark_ok(&self, id: &ServerId) {
        let mut g = self.map.lock();
        let e = g.entry(id.clone()).or_insert_with(ServerFeatures::fresh);
        e.consecutive_failures = 0;
    }

    pub fn needs_probe(&self, id: &ServerId, every: Duration) -> bool {
        match self.get(id).last_probe {
            None => true,
            Some(t) => t.elapsed() >= every,
        }
    }
}

impl Default for FeatureTable {
    fn default() -> Self {
        Self::new()
    }
}
