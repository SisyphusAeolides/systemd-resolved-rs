//! mDNS / DNS-SD minimum for ResolveService + .local

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use parking_lot::RwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdnsMode {
    No,
    Resolve,
    Yes,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ServiceType {
    pub kind: String,   // _ssh._tcp
    pub domain: String, // local
}

#[derive(Clone, Debug)]
pub struct ServiceInstance {
    pub instance: String,
    pub service: ServiceType,
    pub port: u16,
    pub target_host: String,
    pub txt: Vec<(String, Vec<u8>)>,
    pub ifindex: i32,
}

#[derive(Clone, Debug)]
pub struct ResolvedService {
    pub instance: ServiceInstance,
    pub addresses: Vec<IpAddr>,
}

#[derive(Default, Debug)]
pub struct MdnsEngine {
    pub modes: RwLock<HashMap<i32, MdnsMode>>,
    pub services: RwLock<Vec<ServiceInstance>>,
    pub host_addrs: RwLock<HashMap<String, Vec<IpAddr>>>,
}

impl MdnsEngine {
    pub const PORT: u16 = 5353;

    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_mode(&self, ifindex: i32, mode: MdnsMode) {
        self.modes.write().insert(ifindex, mode);
    }

    pub fn register_service(&self, svc: ServiceInstance) {
        self.services.write().push(svc);
    }

    pub async fn resolve_service(
        &self,
        name: &str,
        stype: Option<&str>,
        domain: &str,
        _ifindex: Option<i32>,
    ) -> Option<ResolvedService> {
        let domain = domain.trim_end_matches('.');
        let g = self.services.read();
        let found = g.iter().find(|s| {
            s.service.domain.eq_ignore_ascii_case(domain)
                && (stype.is_none()
                    || s.service
                        .kind
                        .eq_ignore_ascii_case(stype.unwrap_or("")))
                && (s.instance.eq_ignore_ascii_case(name)
                    || format!(
                        "{}.{}.{}",
                        s.instance, s.service.kind, s.service.domain
                    )
                    .eq_ignore_ascii_case(name))
        })?;
        let addrs = self
            .host_addrs
            .read()
            .get(&found.target_host.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default();
        Some(ResolvedService {
            instance: found.clone(),
            addresses: addrs,
        })
    }

    pub fn lookup_local_a(&self, host: &str) -> Vec<IpAddr> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if !h.ends_with(".local") {
            return vec![];
        }
        self.host_addrs
            .read()
            .get(&h)
            .cloned()
            .unwrap_or_default()
    }
}
