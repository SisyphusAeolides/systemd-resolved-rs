// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::wire::{age_ttls, cache_lifetime, rewrite_id, Header, WireError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const STRANGE_RCODE_TTL: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CacheKey {
    pub name: Vec<u8>,
    pub rr_type: u16,
    pub class: u16,
    pub checking_disabled: bool,
    pub route: u64,
}

#[derive(Clone, Debug)]
struct Entry {
    packet: Arc<Vec<u8>>,
    inserted: Instant,
    expires: Instant,
    stale_until: Instant,
    generation: u64,
}

#[derive(Debug)]
struct State {
    entries: HashMap<CacheKey, Entry>,
    next_generation: u64,
}

#[derive(Debug)]
pub struct Cache {
    state: Mutex<State>,
    capacity: usize,
    maximum_ttl: Duration,
    stale_retention: Duration,
    cache_negative: bool,
}

impl Cache {
    pub fn new(
        capacity: usize,
        maximum_ttl: Duration,
        stale_retention: Duration,
        cache_negative: bool,
    ) -> Self {
        Self {
            state: Mutex::new(State {
                entries: HashMap::new(),
                next_generation: 1,
            }),
            capacity,
            maximum_ttl,
            stale_retention,
            cache_negative,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn get(&self, key: &CacheKey, id: u16, allow_stale: bool) -> Option<Vec<u8>> {
        let now = Instant::now();
        let (packet, inserted, is_stale, generation) = {
            let mut state = self.state();
            let entry = state.entries.get(key)?;
            let is_stale = now >= entry.expires;
            if is_stale && (!allow_stale || now >= entry.stale_until) {
                state.entries.remove(key);
                return None;
            }
            (
                Arc::clone(&entry.packet),
                entry.inserted,
                is_stale,
                entry.generation,
            )
        };

        let elapsed = now.saturating_duration_since(inserted).as_secs();
        let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
        let mut packet = (*packet).clone();
        if rewrite_id(&mut packet, id).is_err() || age_ttls(&mut packet, elapsed, is_stale).is_err()
        {
            let mut state = self.state();
            if state
                .entries
                .get(key)
                .is_some_and(|entry| entry.generation == generation)
            {
                state.entries.remove(key);
            }
            return None;
        }
        Some(packet)
    }

    pub fn insert(&self, key: CacheKey, response: &[u8]) -> Result<bool, WireError> {
        let header = Header::parse(response)?;
        if !header.is_response() || header.truncated() {
            return Ok(false);
        }

        let rcode = header.response_code();
        let negative = rcode != 0 || header.answer_count == 0;
        if negative && !self.cache_negative {
            return Ok(false);
        }

        let ttl = match rcode {
            0 | 3 => {
                let Some(ttl_seconds) = cache_lifetime(response)? else {
                    return Ok(false);
                };
                Duration::from_secs(u64::from(ttl_seconds))
            }
            2 => STRANGE_RCODE_TTL,
            _ => return Ok(false),
        }
        .min(self.maximum_ttl);

        if ttl.is_zero() || self.capacity == 0 {
            return Ok(false);
        }

        let now = Instant::now();
        let expires = now.checked_add(ttl).unwrap_or(now);
        let stale_until = expires.checked_add(self.stale_retention).unwrap_or(expires);
        let mut packet = response.to_vec();
        rewrite_id(&mut packet, 0)?;

        let mut state = self.state();
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1).max(1);
        state.entries.insert(
            key,
            Entry {
                packet: Arc::new(packet),
                inserted: now,
                expires,
                stale_until,
                generation,
            },
        );
        while state.entries.len() > self.capacity {
            let oldest = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.generation)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                state.entries.remove(&oldest);
            } else {
                break;
            }
        }
        Ok(true)
    }

    pub fn flush(&self) {
        self.state().entries.clear();
    }

    pub fn len(&self) -> usize {
        self.state().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{local_response, make_query, LocalRecord, TYPE_A};
    use std::net::Ipv4Addr;

    fn key() -> CacheKey {
        CacheKey {
            name: vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0],
            rr_type: TYPE_A,
            class: 1,
            checking_disabled: false,
            route: 0,
        }
    }

    fn servfail_response(id: u16) -> Vec<u8> {
        let mut response = make_query("example", TYPE_A, id).expect("query");
        response[2] |= 0x80;
        response[3] = (response[3] & 0xf0) | 2;
        response
    }

    #[test]
    fn rewrites_transaction_identity() {
        let cache = Cache::new(16, Duration::from_secs(60), Duration::ZERO, true);
        let query = make_query("example", TYPE_A, 7).expect("query");
        let response = local_response(&query, &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))], 30)
            .expect("response");
        assert!(cache.insert(key(), &response).expect("cache insert"));
        let hit = cache.get(&key(), 99, false).expect("cache hit");
        assert_eq!(&hit[..2], &99u16.to_be_bytes());
    }

    #[test]
    fn concurrent_hits_keep_transaction_ids_isolated() {
        let cache = std::sync::Arc::new(Cache::new(
            16,
            Duration::from_secs(60),
            Duration::ZERO,
            true,
        ));
        let query = make_query("example", TYPE_A, 7).expect("query");
        let response = local_response(&query, &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))], 30)
            .expect("response");
        assert!(cache.insert(key(), &response).expect("cache insert"));

        let mut workers = Vec::new();
        for id in 100u16..116 {
            let cache = std::sync::Arc::clone(&cache);
            workers.push(std::thread::spawn(move || {
                let hit = cache.get(&key(), id, false).expect("cache hit");
                assert_eq!(&hit[..2], &id.to_be_bytes());
            }));
        }
        for worker in workers {
            worker.join().expect("cache worker");
        }
    }

    #[test]
    fn capacity_is_enforced() {
        let cache = Cache::new(1, Duration::from_secs(60), Duration::ZERO, true);
        let query = make_query("example", TYPE_A, 7).expect("query");
        let response = local_response(&query, &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))], 30)
            .expect("response");
        assert!(cache.insert(key(), &response).expect("first insert"));
        let mut second = key();
        second.name = vec![6, b's', b'e', b'c', b'o', b'n', b'd', 0];
        assert!(cache.insert(second, &response).expect("second insert"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn servfail_is_cached_when_negative_caching_is_enabled() {
        let cache = Cache::new(16, Duration::from_secs(60), Duration::ZERO, true);
        let response = servfail_response(7);
        assert!(cache.insert(key(), &response).expect("SERVFAIL insert"));
        let hit = cache.get(&key(), 99, false).expect("SERVFAIL cache hit");
        assert_eq!(Header::parse(&hit).expect("header").response_code(), 2);
    }

    #[test]
    fn no_negative_mode_rejects_servfail() {
        let cache = Cache::new(16, Duration::from_secs(60), Duration::ZERO, false);
        let response = servfail_response(7);
        assert!(!cache.insert(key(), &response).expect("SERVFAIL insert"));
        assert!(cache.is_empty());
    }
}
