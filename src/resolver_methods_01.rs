impl Resolver {
    pub fn new(config: Config) -> Self {
        let global_servers = config.configured_upstreams();
        let fallback_servers = config.configured_fallback_upstreams();
        let mut states = HashMap::new();
        for server in &global_servers {
            states
                .entry(ServerKey::new(ScopeKind::Global, *server))
                .or_default();
        }
        for server in &fallback_servers {
            states
                .entry(ServerKey::new(ScopeKind::Fallback, *server))
                .or_default();
        }
        let hosts = if config.read_etc_hosts {
            Hosts::load(&config.hosts_path).unwrap_or_default()
        } else {
            Hosts::default()
        };
        Self {
            cache: Cache::new(
                config.cache_size,
                config.cache_max_ttl,
                config.stale_retention,
                config.cache_negative,
            ),
            config,
            global_servers,
            fallback_servers,
            states: Mutex::new(states),
            udp_sockets: Mutex::new(HashMap::new()),
            tcp_streams: Mutex::new(HashMap::new()),
            routing: RwLock::new(RoutingTable::default()),
            routing_generation: AtomicU64::new(1),
            inflight: Inflight::default(),
            hosts: RwLock::new(hosts),
            next_id: AtomicU16::new(1),
            counters: Counters::default(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn states(&self) -> MutexGuard<'_, HashMap<ServerKey, ServerState>> {
        self.states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn routing(&self) -> RwLockReadGuard<'_, RoutingTable> {
        self.routing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn routing_mut(&self) -> RwLockWriteGuard<'_, RoutingTable> {
        self.routing
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn links(&self) -> Vec<LinkState> {
        self.routing().links()
    }

    pub fn link(&self, ifindex: i32) -> Option<LinkState> {
        self.routing().link(ifindex)
    }

    pub fn set_link_dns(&self, ifindex: i32, servers: Vec<SocketAddr>) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_dns(ifindex, servers)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_domains(&self, ifindex: i32, domains: Vec<Domain>) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_domains(ifindex, domains)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_default_route(
        &self,
        ifindex: i32,
        default_route: Option<bool>,
    ) -> Result<(), LinkError> {
        let changed = self
            .routing_mut()
            .set_default_route(ifindex, default_route)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_llmnr(&self, ifindex: i32, mode: SupportMode) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_llmnr(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_multicast_dns(&self, ifindex: i32, mode: SupportMode) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_multicast_dns(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dns_over_tls(&self, ifindex: i32, mode: TlsMode) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_dns_over_tls(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dnssec(&self, ifindex: i32, mode: ValidationMode) -> Result<(), LinkError> {
        let changed = self.routing_mut().set_dnssec(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dnssec_negative_trust_anchors(
        &self,
        ifindex: i32,
        anchors: Vec<String>,
    ) -> Result<(), LinkError> {
        let changed = self
            .routing_mut()
            .set_dnssec_negative_trust_anchors(ifindex, anchors)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn revert_link(&self, ifindex: i32) -> Result<(), LinkError> {
        let changed = self.routing_mut().revert(ifindex)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    fn finish_routing_change(&self, changed: bool) {
        if changed {
            self.routing_generation.fetch_add(1, Ordering::AcqRel);
            self.cache.flush();
        }
    }

    fn search_domains(&self, ifindex: Option<i32>) -> Result<Vec<Domain>, ResolveError> {
        Ok(self
            .routing()
            .search_domains(&self.config.domains, ifindex)?)
    }

    fn hosts(&self) -> RwLockReadGuard<'_, Hosts> {
        self.hosts
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
