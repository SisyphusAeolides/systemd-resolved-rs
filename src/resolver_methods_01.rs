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
            networkd_links: RwLock::new(HashMap::new()),
            link_server_specs: RwLock::new(HashMap::new()),
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

    fn networkd_links(&self) -> RwLockReadGuard<'_, HashMap<i32, NetworkdLinkState>> {
        self.networkd_links
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn networkd_links_mut(&self) -> RwLockWriteGuard<'_, HashMap<i32, NetworkdLinkState>> {
        self.networkd_links
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn links(&self) -> Vec<LinkState> {
        self.routing().links()
    }

    pub fn link(&self, ifindex: i32) -> Option<LinkState> {
        self.routing().link(ifindex)
    }

    pub fn link_is_managed(&self, ifindex: i32) -> bool {
        self.networkd_links()
            .get(&ifindex)
            .is_some_and(|link| link.managed)
    }

    fn networkd_link_relevant(&self, ifindex: i32) -> bool {
        self.networkd_links()
            .get(&ifindex)
            .map_or(true, NetworkdLinkState::resolver_relevant)
    }

    fn ensure_link_writable(&self, ifindex: i32) -> Result<(), LinkError> {
        if self.link_is_managed(ifindex) {
            Err(LinkError::ManagedLink(ifindex))
        } else {
            Ok(())
        }
    }

    pub fn sync_kernel_links(
        &self,
        links: Vec<crate::routing::KernelLinkState>,
    ) -> Result<(), LinkError> {
        let route_changed = self.routing_mut().sync_kernel_links(links)?;
        let live_ifindices = self
            .routing()
            .links()
            .into_iter()
            .map(|link| link.ifindex)
            .collect::<HashSet<_>>();
        let identity_changed = {
            let mut specs = self.link_server_specs_mut();
            let before = specs.len();
            specs.retain(|ifindex, _| live_ifindices.contains(ifindex));
            specs.len() != before
        };
        self.finish_routing_change(route_changed || identity_changed);
        Ok(())
    }

    pub fn sync_networkd_links(&self, links: Vec<NetworkdLinkState>) -> Result<(), LinkError> {
        let incoming = links
            .into_iter()
            .map(|link| (link.ifindex, link))
            .collect::<HashMap<_, _>>();
        let mut networkd = self.networkd_links_mut();
        let mut routing = self.routing_mut();
        let mut changed = false;
        let mut removed_identities = Vec::new();
        let mut managed_identities = Vec::new();

        for (&ifindex, previous) in networkd.iter() {
            let still_managed = incoming.get(&ifindex).is_some_and(|link| link.managed);
            if previous.managed && !still_managed {
                removed_identities.push(ifindex);
                if routing.link(ifindex).is_some() {
                    changed |= routing.revert(ifindex)?;
                }
            }
        }

        for link in incoming.values().filter(|link| link.managed) {
            if routing.link(link.ifindex).is_none() {
                removed_identities.push(link.ifindex);
                continue;
            }
            changed |= routing.set_dns(link.ifindex, link.dns_servers.clone())?;
            changed |= routing.set_domains(link.ifindex, link.domains.clone())?;
            changed |= routing.set_default_route(link.ifindex, link.default_route)?;
            changed |= routing.set_llmnr(link.ifindex, link.llmnr)?;
            changed |= routing.set_multicast_dns(link.ifindex, link.multicast_dns)?;
            changed |= routing.set_dns_over_tls(
                link.ifindex,
                link.dns_over_tls.unwrap_or(self.config.dns_over_tls),
            )?;
            changed |= routing.set_dnssec(
                link.ifindex,
                link.dnssec.unwrap_or(self.config.dnssec),
            )?;
            changed |= routing.set_dnssec_negative_trust_anchors(
                link.ifindex,
                link.dnssec_negative_trust_anchors.clone(),
            )?;
            if let Some(state) = routing.link(link.ifindex) {
                managed_identities.push((
                    link.ifindex,
                    state.dns_servers,
                    link.dns_server_specs.clone(),
                ));
            }
        }

        *networkd = incoming;
        drop(routing);
        drop(networkd);

        let mut identity_changed = false;
        for ifindex in removed_identities {
            identity_changed |= self.remove_link_server_specs(ifindex);
        }
        for (ifindex, servers, specs) in managed_identities {
            let specs = if specs.is_empty() {
                servers
                    .into_iter()
                    .map(|address| DnsServerSpec {
                        address,
                        interface: None,
                        server_name: None,
                    })
                    .collect()
            } else {
                normalize_link_specs(&servers, specs)
            };
            identity_changed |= self.replace_link_server_specs(ifindex, specs);
        }
        self.finish_routing_change(changed || identity_changed);
        Ok(())
    }

    pub fn set_link_dns(&self, ifindex: i32, servers: Vec<SocketAddr>) -> Result<(), LinkError> {
        let specs = servers
            .into_iter()
            .map(|address| DnsServerSpec {
                address,
                interface: None,
                server_name: None,
            })
            .collect();
        self.set_link_dns_specs(ifindex, specs)
    }

    pub fn set_link_domains(&self, ifindex: i32, domains: Vec<Domain>) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self.routing_mut().set_domains(ifindex, domains)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_default_route(
        &self,
        ifindex: i32,
        default_route: Option<bool>,
    ) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self
            .routing_mut()
            .set_default_route(ifindex, default_route)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_llmnr(&self, ifindex: i32, mode: SupportMode) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self.routing_mut().set_llmnr(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_multicast_dns(&self, ifindex: i32, mode: SupportMode) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self.routing_mut().set_multicast_dns(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dns_over_tls(&self, ifindex: i32, mode: TlsMode) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self.routing_mut().set_dns_over_tls(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dnssec(&self, ifindex: i32, mode: ValidationMode) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self.routing_mut().set_dnssec(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dnssec_negative_trust_anchors(
        &self,
        ifindex: i32,
        anchors: Vec<String>,
    ) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self
            .routing_mut()
            .set_dnssec_negative_trust_anchors(ifindex, anchors)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn revert_link(&self, ifindex: i32) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let route_changed = self.routing_mut().revert(ifindex)?;
        let identity_changed = self.remove_link_server_specs(ifindex);
        self.finish_routing_change(route_changed || identity_changed);
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
