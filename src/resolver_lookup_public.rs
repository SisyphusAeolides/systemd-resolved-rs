impl Resolver {
    pub fn lookup_address(&self, address: IpAddr) -> Result<AddressLookup, ResolveError> {
        self.lookup_address_on_link(address, None)
    }

    pub fn lookup_address_on_link(
        &self,
        address: IpAddr,
        ifindex: Option<i32>,
    ) -> Result<AddressLookup, ResolveError> {
        let (response, _) =
            self.query_following_redirects(
                &reverse_name(address),
                wire::CLASS_IN,
                TYPE_PTR,
                ifindex,
            )?;
        let names = extract_ptr_names(&response)?;
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
        self.query_following_redirects(name, class, rr_type, ifindex)
            .map(|(response, _)| response)
    }

    pub fn reload_hosts(&self) -> io::Result<()> {
        let hosts = if self.config.read_etc_hosts {
            Hosts::load(&self.config.hosts_path)?
        } else {
            Hosts::default()
        };
        *self.hosts_mut() = hosts;
        crate::static_records::invalidate_system();
        Ok(())
    }

    pub fn flush_cache(&self) {
        self.cache.flush();
    }

    pub fn reset_server_features(&self) {
        for state in self.states().values_mut() {
            state.metric = ServerMetric::default();
            state.cooldown_until = None;
            state.features.reset();
            state.transport.reset();
            state.missing_root_rrsig = false;
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
