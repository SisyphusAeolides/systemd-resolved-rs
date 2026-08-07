#![allow(missing_debug_implementations)]
pub mod budget;
pub mod dataplane;
pub mod disk_cache;
pub mod l2_cache;
pub mod nsec_agg;
pub mod obs;
pub mod policy;
pub mod prefetch;
pub mod shm;
pub mod sigcache;
pub mod swr;
pub mod transport_pool;

use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::supremacy::budget::{QueryBudget, QueryClass};
use crate::supremacy::l2_cache::{CKey, CVal, DnssecMark, L2Cache};
use crate::supremacy::nsec_agg::{AggAnswer, AggressiveNsec};
use crate::supremacy::obs::{FlightEvent, FlightRecorder, Metrics};
use crate::supremacy::prefetch::PrefetchEngine;
use crate::supremacy::shm::ShmPublisher;
use crate::supremacy::sigcache::SigCache;
use crate::supremacy::swr::{decide_swr, SwrConfig, SwrDecision};
use crate::supremacy::transport_pool::TransportPool;
use bytes::Bytes;

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
            cache: L2Cache::new(6, 8192, swr),
            nsec: AggressiveNsec::new(),
            sigcache: Arc::new(SigCache::new(65536)),
            pool: TransportPool::new(4, 4096),
            prefetch: PrefetchEngine::new(),
            metrics: Arc::new(Metrics::default()),
            flight: FlightRecorder::new(1024),
            shm: Mutex::new(ShmPublisher::create().ok()),
            swr,
        })
    }

    pub async fn resolve(&self, key: CKey, class: QueryClass) -> Result<CVal, SupremacyErr> {
        let start = Instant::now();
        self.metrics.queries_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let budget = QueryBudget::new(class);
        let now = Instant::now();

        // 1) L2 + SWR
        let ent = self.cache.get_entry(&key);
        match decide_swr(ent.as_ref(), now, &self.swr, &budget) {
            SwrDecision::Serve(v, kick) => {
                if ent.as_ref().map(|e| now >= e.expires).unwrap_or(false) {
                    self.metrics.swr_served.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                self.prefetch.record_hit(&key);
                if kick {
                    // background refresh — spawn
                }
                self.metrics.record_latency(start.elapsed());
                return Ok(v);
            }
            SwrDecision::MustFetch => {}
        }

        // 2) Aggressive NSEC
        match self.nsec.lookup(&key.owner, key.qtype, now) {
            AggAnswer::NxDomain => {
                self.metrics.nsec_agg_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let v = CVal {
                    rcode: 3,
                    answer: Bytes::new(),
                    dnssec: DnssecMark::Secure,
                    min_ttl: 60,
                    from_upstream: 0,
                };
                self.cache.put(key, v.clone(), Duration::from_secs(60), now);
                return Ok(v);
            }
            AggAnswer::NoData => {
                self.metrics.nsec_agg_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let v = CVal {
                    rcode: 0,
                    answer: Bytes::new(),
                    dnssec: DnssecMark::Secure,
                    min_ttl: 60,
                    from_upstream: 0,
                };
                return Ok(v);
            }
            AggAnswer::Miss => {}
        }

        if budget.expired() {
            self.metrics.budget_expired.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // last chance stale
            if let Some((v, true)) = self.cache.get(&key, now) {
                self.metrics.swr_served.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(v);
            }
            return Err(SupremacyErr::Budget);
        }

        // 3) Upstream via pool + HyperResolver speculative (integrate)
        let result = self.fetch_upstream(&key, &budget).await;
        match result {
            Ok(v) => {
                self.cache.put(
                    key.clone(),
                    v.clone(),
                    Duration::from_secs(v.min_ttl as u64),
                    Instant::now(),
                );
                self.publish_shm(&key, &v);
                self.metrics.upstream_ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics.record_latency(start.elapsed());
                Ok(v)
            }
            Err(e) => {
                self.metrics.upstream_fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // SWR fallback
                if let Some((v, true)) = self.cache.get(&key, Instant::now()) {
                    self.metrics.swr_served.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(v);
                }
                self.flight.push(FlightEvent {
                    at: Instant::now(),
                    qname: format!("{:?}", key.owner),
                    qtype: key.qtype,
                    err: format!("{:?}", e),
                    upstream: None,
                    budget_ms_left: budget.remaining().as_millis() as u64,
                    wire_hex_prefix: String::new(),
                });
                Err(e)
            }
        }
    }

    async fn fetch_upstream(&self, _key: &CKey, _budget: &QueryBudget) -> Result<CVal, SupremacyErr> {
        // Hook: SpeculativePool + TransportPool + dnssec sigcache
        Err(SupremacyErr::Upstream)
    }

    fn publish_shm(&self, key: &CKey, val: &CVal) {
        // extract A/AAAA → ShmPublisher::publish_addrs
        let _ = (key, val);
        let _ = self.shm.lock();
    }
}

#[derive(Debug)]
pub enum SupremacyErr {
    Budget,
    Upstream,
    DnssecBogus,
    PolicyBlackhole,
}
