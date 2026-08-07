// SPDX-License-Identifier: LGPL-2.1-or-later
use super::dnssd_config::{DnsSdConfigError, ServiceCatalog};
use super::parity::MdnsInterface;
use super::parity_dnssd::{DnsSdError, DnsSdRecord};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const RELOAD_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum DnsSdRuntimeError {
    Configuration(DnsSdConfigError),
    Service(DnsSdError),
}

impl fmt::Display for DnsSdRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => error.fmt(formatter),
            Self::Service(error) => error.fmt(formatter),
        }
    }
}

impl Error for DnsSdRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Service(error) => Some(error),
        }
    }
}

impl From<DnsSdConfigError> for DnsSdRuntimeError {
    fn from(error: DnsSdConfigError) -> Self {
        Self::Configuration(error)
    }
}

impl From<DnsSdError> for DnsSdRuntimeError {
    fn from(error: DnsSdError) -> Self {
        Self::Service(error)
    }
}

#[derive(Debug)]
struct CatalogState {
    catalog: ServiceCatalog,
    next_reload: Instant,
    last_error: Option<String>,
}

impl CatalogState {
    fn new() -> Self {
        match ServiceCatalog::load() {
            Ok(catalog) => Self {
                catalog,
                next_reload: Instant::now() + RELOAD_INTERVAL,
                last_error: None,
            },
            Err(error) => Self {
                catalog: ServiceCatalog::default(),
                next_reload: Instant::now() + RELOAD_INTERVAL,
                last_error: Some(error.to_string()),
            },
        }
    }

    fn refresh(&mut self, now: Instant) {
        if now < self.next_reload {
            return;
        }
        self.next_reload = now + RELOAD_INTERVAL;
        match ServiceCatalog::load() {
            Ok(loaded) => {
                self.catalog.reconcile(loaded);
                self.last_error = None;
            }
            Err(error) => {
                let message = error.to_string();
                if self.last_error.as_deref() != Some(&message) {
                    eprintln!("systemd-resolved: DNS-SD reload failed: {message}");
                }
                self.last_error = Some(message);
            }
        }
    }
}

static CATALOG: OnceLock<Mutex<CatalogState>> = OnceLock::new();

fn state() -> MutexGuard<'static, CatalogState> {
    CATALOG
        .get_or_init(|| Mutex::new(CatalogState::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn records_for(
    interface: MdnsInterface,
    addresses: &BTreeSet<IpAddr>,
    host_label: &str,
    goodbye: bool,
) -> Result<Vec<DnsSdRecord>, DnsSdRuntimeError> {
    let mut state = state();
    state.refresh(Instant::now());
    Ok(state
        .catalog
        .records_for(interface, addresses, host_label, goodbye)?)
}

pub fn instance_owners(
    interface: MdnsInterface,
    addresses: &BTreeSet<IpAddr>,
    host_label: &str,
) -> Result<BTreeMap<Vec<u8>, String>, DnsSdRuntimeError> {
    let mut state = state();
    state.refresh(Instant::now());
    Ok(state
        .catalog
        .instance_owners(interface, addresses, host_label)?)
}

pub fn rename_conflicting_owner(
    owner: &[u8],
    rr_type: u16,
    interface: MdnsInterface,
    addresses: &BTreeSet<IpAddr>,
    host_label: &str,
) -> Result<Option<String>, DnsSdRuntimeError> {
    let mut state = state();
    state.refresh(Instant::now());
    Ok(state.catalog.rename_conflicting_owner(
        owner,
        rr_type,
        interface,
        addresses,
        host_label,
    )?)
}

pub fn generation() -> u64 {
    let mut state = state();
    state.refresh(Instant::now());
    state.catalog.generation()
}

pub fn force_reload() -> Result<bool, DnsSdRuntimeError> {
    let loaded = ServiceCatalog::load()?;
    let mut state = state();
    state.next_reload = Instant::now() + RELOAD_INTERVAL;
    state.last_error = None;
    Ok(state.catalog.reconcile(loaded))
}

pub fn flush() {
    let mut state = state();
    state.catalog = ServiceCatalog::default();
    state.next_reload = Instant::now();
    state.last_error = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_global_catalog_is_safe() {
        flush();
        let interface = MdnsInterface::new(2, super::super::parity::MdnsAddressFamily::Ipv4);
        assert!(records_for(interface, &BTreeSet::new(), "host", false)
            .expect("empty records")
            .is_empty());
    }
}
