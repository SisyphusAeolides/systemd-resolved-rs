//! landing_glue.rs — single place that starts a replaceable resolved.
//!
//! Call: landing_glue::run(cfg).await

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

// Adjust paths to your real modules as you merge:
// use crate::config::ResolvedConfig;
// use crate::supremacy::{Dataplane, DataplaneConfig, SupremacyResolver, Metrics, serve_metrics};
// use crate::resolvconf_publish::{ResolvConfPublisher, ResolvConfMode, GlobalDnsState};
// use crate::lifecycle;

#[derive(Debug)]
pub struct LandingConfig {
    pub stub_addr: SocketAddr,
    pub workers: usize,
    pub run_dir: PathBuf,
    pub metrics_addr: Option<String>,
    pub shm_l1: bool,
    pub swr: bool,
}

impl Default for LandingConfig {
    fn default() -> Self {
        Self {
            stub_addr: "127.0.0.53:53".parse().unwrap(),
            workers: 0, // 0 = auto
            run_dir: PathBuf::from("/run/systemd/resolve"),
            metrics_addr: Some("127.0.0.1:9990".into()),
            shm_l1: true,
            swr: true,
        }
    }
}

pub async fn run(landing: LandingConfig /*, cfg: ResolvedConfig */) -> anyhow::Result<()> {
    // 1) State dir + resolv.conf
    std::fs::create_dir_all(&landing.run_dir)?;
    // let publisher = ResolvConfPublisher { run_dir: landing.run_dir.clone(), mode: ResolvConfMode::Stub };
    // publisher.republish(&GlobalDnsState { search: vec![], uplink_servers: vec![] })?;

    // 2) Core resolver (supremacy or existing Resolver)
    // let core = SupremacyResolver::new();

    // 3) Control plane tasks (D-Bus + Varlink) — non-blocking
    // tokio::spawn(dbus::run(core.clone(), cfg.clone()));
    // tokio::spawn(varlink::run(core.clone(), "/run/systemd/resolve/io.systemd.Resolve"));

    // 4) Netlink/networkd watchers
    // tokio::spawn(networkd::watch(core.clone()));

    // 5) Metrics
    if let Some(addr) = landing.metrics_addr.clone() {
        // let m = core.metrics.clone();
        // tokio::spawn(async move { let _ = serve_metrics(m, &addr).await; });
        info!(%addr, "metrics enabled");
    }

    // 6) Notify systemd BEFORE heavy listen if socket-activated;
    //    else listen then notify.
    crate::lifecycle::sd_notify_ready();
    info!("READY=1 (call sd_notify here)");

    // 7) Watchdog loop
    tokio::spawn(async {
        let mut iv = tokio::time::interval(Duration::from_secs(15));
        loop {
            iv.tick().await;
            crate::lifecycle::sd_notify_watchdog();
        }
    });

    // 8) Data plane (blocks)
    // let dp = Arc::new(Dataplane { cfg: DataplaneConfig {
    //     bind: landing.stub_addr,
    //     workers: if landing.workers == 0 { 0 } else { landing.workers },
    //     ..Default::default()
    // }, cache: core.cache.clone() });
    // dp.run().await?;

    // Placeholder until Dataplane merged:
    warn!("landing_glue: dataplane not linked — bind stub in daemon.rs");
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
