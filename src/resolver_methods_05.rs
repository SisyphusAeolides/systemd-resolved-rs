impl Resolver {
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
