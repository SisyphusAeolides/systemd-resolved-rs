//! Single entry: start control plane + dataplane + resolv.conf + notify.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use crate::lifecycle;
use crate::resolvconf_publish::{GlobalDnsState, ResolvConfMode, ResolvConfPublisher};
use crate::supremacy::{Dataplane, DataplaneConfig};
use crate::supremacy::SupremacyResolver;

#[derive(Clone, Debug)]
pub struct LandingConfig {
    pub stub_addr: SocketAddr,
    pub workers: usize,
    pub run_dir: PathBuf,
    pub metrics_addr: Option<String>,
    pub shm_l1: bool,
    pub search: Vec<String>,
    pub uplink: Vec<IpAddr>,
}

impl Default for LandingConfig {
    fn default() -> Self {
        Self {
            stub_addr: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 53), 53)),
            workers: 0,
            run_dir: PathBuf::from("/run/systemd/resolve"),
            metrics_addr: std::env::var("RESOLVED_RS_METRICS").ok(),
            shm_l1: std::env::var("RESOLVED_RS_SHM").map(|v| v != "0").unwrap_or(true),
            search: vec![],
            uplink: vec![],
        }
    }
}

pub async fn run(mut landing: LandingConfig) -> anyhow::Result<()> {
    lifecycle::install_signal_handlers();

    let publisher = ResolvConfPublisher {
        run_dir: landing.run_dir.clone(),
        mode: ResolvConfMode::Stub,
    };
    let state = GlobalDnsState {
        search: landing.search.clone(),
        uplink_servers: landing.uplink.clone(),
        options: vec!["edns0".into(), "trust-ad".into()],
    };
    if let Err(e) = publisher.republish(&state) {
        warn!(error = %e, "resolv.conf publish failed (continuing)");
    }

    // Core supremacy resolver
    let core = SupremacyResolver::new();

    // Metrics HTTP
    if let Some(addr) = landing.metrics_addr.clone() {
        let m = Arc::clone(&core.metrics);
        tokio::spawn(async move {
            if let Err(e) = crate::supremacy::obs::serve_metrics(m, &addr).await {
                error!(error = %e, "metrics server exited");
            }
        });
    }

    // Watchdog + reload/flush
    let core_bg = Arc::clone(&core);
    let pub_bg = publisher.clone();
    let state_bg = state.clone();
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(15));
        loop {
            iv.tick().await;
            lifecycle::sd_notify_watchdog();
            if lifecycle::take_reload() {
                info!("SIGHUP reload");
                let _ = pub_bg.republish(&state_bg);
            }
            if lifecycle::take_flush() {
                info!("SIGUSR2 flush caches");
                core_bg.cache.flush();
            }
            if lifecycle::stop_requested() {
                lifecycle::sd_notify_stopping();
                break;
            }
        }
    });

    // TODO: spawn dbus + varlink control plane here with core.clone()
    // tokio::spawn(crate::dbus::run(...));
    // tokio::spawn(crate::varlink::run(...));

    lifecycle::sd_notify_ready();
    info!(stub = %landing.stub_addr, "READY=1");

    let workers = if landing.workers == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get().clamp(2, 16))
            .unwrap_or(4)
    } else {
        landing.workers
    };

    let dp = Arc::new(Dataplane {
        cfg: DataplaneConfig {
            bind: landing.stub_addr,
            workers,
            recvmmsg_batch: 32,
        },
        cache: Arc::clone(&core.cache),
    });

    // Run dataplane until stop
    let dp_run = Arc::clone(&dp);
    let handle = tokio::spawn(async move {
        if let Err(e) = dp_run.run().await {
            error!(error = %e, "dataplane error");
        }
    });

    while !lifecycle::stop_requested() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    handle.abort();
    Ok(())
}
