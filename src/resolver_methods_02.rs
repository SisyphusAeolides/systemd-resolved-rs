impl Resolver {
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
        include!("resolver_query_on_link.rs")
    }

    pub fn query_or_servfail(&self, query: &[u8], mode: QueryMode) -> Result<Vec<u8>, WireError> {
        match self.query(query, mode) {
            Ok(response) => Ok(response),
            Err(_) => servfail_for(query),
        }
    }
}
