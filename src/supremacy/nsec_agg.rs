//! Answer NXDOMAIN/NODATA from cached NSEC/NSEC3 ranges without upstream.
#![allow(missing_debug_implementations)]

use std::collections::BTreeMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct NsecRange {
    pub zone: Vec<u8>,       // wire apex
    pub owner: Vec<u8>,      // owner name wire or hash label parent
    pub next: Vec<u8>,
    pub types: bitflags_types::TypeBitmap, // see below simplified
    pub expires: Instant,
    pub secure: bool,
    pub nsec3: bool,
    pub nsec3_params: Option<Nsec3Params>,
    pub owner_hash: Option<Vec<u8>>,
    pub next_hash: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Nsec3Params {
    pub hash_alg: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}

// simplified type bitmap
pub mod bitflags_types {
    #[derive(Clone, Debug, Default)]
    pub struct TypeBitmap {
        pub bits: Vec<u8>,
    }
    impl TypeBitmap {
        pub fn contains(&self, rrtype: u16) -> bool {
            let block = (rrtype / 256) as usize;
            let bit = (rrtype % 256) as usize;
            // real impl parses window blocks; stub:
            let _ = (block, bit);
            false
        }
    }
}

#[derive(Default)]
pub struct AggressiveNsec {
    /// keyed by zone apex wire
    zones: RwLock<BTreeMap<Vec<u8>, Vec<NsecRange>>>,
    hits: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Debug)]
pub enum AggAnswer {
    NxDomain,
    NoData,
    /// must go upstream
    Miss,
}

impl AggressiveNsec {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert_ranges(&self, ranges: Vec<NsecRange>) {
        let mut g = self.zones.write();
        for r in ranges {
            g.entry(r.zone.clone()).or_default().push(r);
        }
    }

    pub fn lookup(&self, qname: &[u8], qtype: u16, now: Instant) -> AggAnswer {
        // Find best zone cut (longest apex match) — simplified: try all
        let g = self.zones.read();
        for (_apex, ranges) in g.iter() {
            for r in ranges {
                if r.expires <= now || !r.secure {
                    continue;
                }
                if r.nsec3 {
                    if let (Some(oh), Some(nh), Some(p)) =
                        (&r.owner_hash, &r.next_hash, &r.nsec3_params)
                    {
                        let qh = nsec3_hash(p, qname);
                        if hash_covers(oh, nh, &qh) {
                            // closest-encloser logic simplified: if exact owner hash match
                            if &qh == oh {
                                if r.types.contains(qtype) {
                                    return AggAnswer::Miss; // positive exists — shouldn't deny
                                }
                                self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                return AggAnswer::NoData;
                            }
                            // in empty range → nxdomain candidate
                            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return AggAnswer::NxDomain;
                        }
                    }
                } else if name_covers(&r.owner, &r.next, qname) {
                    if r.owner == qname {
                        if r.types.contains(qtype) {
                            return AggAnswer::Miss;
                        }
                        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return AggAnswer::NoData;
                    }
                    self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return AggAnswer::NxDomain;
                }
            }
        }
        AggAnswer::Miss
    }
}

fn name_covers(owner: &[u8], next: &[u8], q: &[u8]) -> bool {
    // canonical owner < q < next (or wrap)
    if owner < next {
        owner < q && q < next
    } else {
        // wrap
        q > owner || q < next
    }
}

fn hash_covers(owner_h: &[u8], next_h: &[u8], qh: &[u8]) -> bool {
    if owner_h < next_h {
        owner_h < qh && qh < next_h
    } else {
        qh > owner_h || qh < next_h
    }
}

pub fn nsec3_hash(p: &Nsec3Params, qname: &[u8]) -> Vec<u8> {
    // SHA-1 iterated — production: ring/openssl
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut msg = qname.to_vec();
    msg.extend_from_slice(&p.salt);
    let mut h = DefaultHasher::new();
    msg.hash(&mut h);
    let mut out = h.finish().to_be_bytes().to_vec();
    for _ in 0..p.iterations {
        let mut hh = DefaultHasher::new();
        out.hash(&mut hh);
        p.salt.hash(&mut hh);
        out = hh.finish().to_be_bytes().to_vec();
    }
    // NOTE: replace with real SHA-1 NSEC3 before production
    out
}
