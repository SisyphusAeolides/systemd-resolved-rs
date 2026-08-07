//! SupremacyResolver — cache + SWR + NSEC agg + metrics + SHM publish hooks.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tracing::debug;

use crate::nss_backend::{build_address_answer, name_to_wire_lower};
use crate::supremacy::budget::{QueryBudget, QueryClass};
use crate::supremacy::l2_cache::{CKey, CVal, DnssecMark, L2Cache};
use crate::supremacy::nsec_agg::{AggAnswer, AggressiveNsec};
use crate::supremacy::obs::{FlightEvent, FlightRecorder, Metrics};
use crate::supremacy::prefetch::PrefetchEngine;
use crate::supremacy::shm::ShmPublisher;
use crate::supremacy::sigcache::SigCache;
use crate::supremacy::swr::{decide_swr, SwrConfig, SwrDecision};
use crate::supremacy::transport_pool::TransportPool;
use parking_lot::Mutex;

#[derive(Debug)]
pub enum SupremacyErr {
    Budget,
    Upstream(String),
    DnssecBogus,
    PolicyBlackhole,
    Name(String),
    Internal(String),
}

impl std::fmt::Display for SupremacyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Budget => write!(f, "query budget exhausted"),
            Self::Upstream(s) => write!(f, "upstream: {s}"),
            Self::DnssecBogus => write!(f, "dnssec bogus"),
            Self::PolicyBlackhole => write!(f, "policy blackhole"),
            Self::Name(s) => write!(f, "name: {s}"),
            Self::Internal(s) => write!(f, "internal: {s}"),
        }
    }
}

impl std::error::Error for SupremacyErr {}

pub struct SupremacyResolver {
    pub cache: Arc<L2Cache>,
    pub nsec: Arc<AggressiveNsec>,
    pub sigcache: Arc<SigCache>,
    pub pool: Arc<TransportPool>,
    pub prefetch: Arc<PrefetchEngine>,
    pub metrics: Arc<Metrics>,
    pub flight: Arc<FlightRecorder>,
    pub shm: Mutex<Option<ShmPublisher>>,
    pub swr: SwrConfig,
}

impl SupremacyResolver {
    pub fn new() -> Arc<Self> {
        let swr = SwrConfig::default();
        Arc::new(Self {
            cache: L2Cache::new(6, 8192, swr.clone()),
            nsec: AggressiveNsec::new(),
            sigcache: Arc::new(SigCache::new(65536)),
            pool: TransportPool::new(4, 4096),
            prefetch: PrefetchEngine::new(),
            metrics: Arc::new(Metrics::default()),
            flight: FlightRecorder::new(2048),
            shm: Mutex::new(ShmPublisher::create().ok()),
            swr,
        })
    }

    pub fn flush_all(&self) {
        self.cache.flush();
    }

    pub async fn resolve_name(
        &self,
        name: &str,
        qtype: u16,
        qclass: u16,
        class: QueryClass,
    ) -> Result<CVal, SupremacyErr> {
        let wire = name_to_wire_lower(name).map_err(|e| SupremacyErr::Name(e.to_string()))?;
        let key = CKey {
            owner: Bytes::from(wire),
            qtype,
            qclass,
            cd: false,
        };
        self.resolve_key(key, class).await
    }

    pub async fn resolve_key(&self, key: CKey, class: QueryClass) -> Result<CVal, SupremacyErr> {
        let start = Instant::now();
        self.metrics
            .queries_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let budget = QueryBudget::new(class);
        let now = Instant::now();

        let ent = self.cache.get_entry(&key);
        match decide_swr(ent.as_ref(), now, &self.swr, &budget) {
            SwrDecision::Serve(v, kick) => {
                if ent.as_ref().map(|e| now >= e.expires).unwrap_or(false) {
                    self.metrics
                        .swr_served
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                } else {
                    self.metrics
                        .cache_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                self.prefetch.record_hit(&key);
                if kick {
                    debug!(?key, "schedule background refresh");
                    // spawn refresh using pool — integrate with your upstream list
                }
                self.metrics.record_latency(start.elapsed());
                return Ok(v);
            }
            SwrDecision::MustFetch => {}
        }

        match self.nsec.lookup(&key.owner, key.qtype, now) {
            AggAnswer::NxDomain => {
                self.metrics
                    .nsec_agg_hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let v = CVal {
                    rcode: 3,
                    answer: Bytes::from(build_soa_nxbits(&key.owner, key.qtype)),
                    dnssec: DnssecMark::Secure,
                    min_ttl: 60,
                    from_upstream: 0,
                };
                self.cache
                    .put(key, v.clone(), Duration::from_secs(60), now);
                return Ok(v);
            }
            AggAnswer::NoData => {
                self.metrics
                    .nsec_agg_hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let v = CVal {
                    rcode: 0,
                    answer: Bytes::new(),
                    dnssec: DnssecMark::Insecure,
                    min_ttl: 60,
                    from_upstream: 0,
                };
                return Ok(v);
            }
            AggAnswer::Miss => {}
        }

        if budget.expired() {
            self.metrics
                .budget_expired
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some((v, true)) = self.cache.get(&key, now) {
                self.metrics
                    .swr_served
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(v);
            }
            return Err(SupremacyErr::Budget);
        }

        match self.fetch_upstream(&key, &budget).await {
            Ok(v) => {
                self.cache.put(
                    key.clone(),
                    v.clone(),
                    Duration::from_secs(v.min_ttl.max(1) as u64),
                    Instant::now(),
                );
                self.publish_shm_if_address(&key, &v);
                self.metrics
                    .upstream_ok
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics.record_latency(start.elapsed());
                Ok(v)
            }
            Err(e) => {
                self.metrics
                    .upstream_fail
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some((v, true)) = self.cache.get(&key, Instant::now()) {
                    self.metrics
                        .swr_served
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(v);
                }
                self.flight.push(FlightEvent {
                    at: Instant::now(),
                    qname: format!("{:?}", key.owner),
                    qtype: key.qtype,
                    err: e.to_string(),
                    upstream: None,
                    budget_ms_left: budget.remaining().as_millis() as u64,
                    wire_hex_prefix: String::new(),
                });
                Err(e)
            }
        }
    }

    async fn fetch_upstream(
        &self,
        key: &CKey,
        budget: &QueryBudget,
    ) -> Result<CVal, SupremacyErr> {
        // Hook your existing Resolver / HyperResolver / routing here.
        // Placeholder returns failure so SWR/negative paths stay testable.
        let _ = (key, budget, &self.pool, &self.sigcache);
        Err(SupremacyErr::Upstream(
            "wire HyperResolver::resolve into SupremacyResolver::fetch_upstream".into(),
        ))
    }

    fn publish_shm_if_address(&self, key: &CKey, val: &CVal) {
        if !matches!(key.qtype, 1 | 28) || val.rcode != 0 {
            return;
        }
        // Parse A/AAAA from val.answer and call ShmPublisher::publish_addrs
        let _ = (key, val, &self.shm);
    }
}

fn build_soa_nxbits(owner: &[u8], qtype: u16) -> Vec<u8> {
    // Minimal empty NXDOMAIN-ish message; real code copies SOA from authority.
    let mut v = vec![0u8; 12];
    v[2] = 0x80;
    v[3] = 0x03; // NXDOMAIN
    v[5] = 1;
    v.extend_from_slice(owner);
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v
}
