//! src/llmnr/mod.rs — experimental LLMNR parity core (RFC 4795)
//! Modes match resolved: yes (resolve+respond), resolve (query only), no.
#![allow(missing_debug_implementations)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::net::UdpSocket;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmnrMode { No, Resolve, Yes }

#[derive(Clone, Debug)]
pub struct LlmnrLinkCfg {
    pub ifindex: i32,
    pub mode: LlmnrMode,
    /// Names we claim on this link (hostname, aliases).
    pub claim_names: Vec<String>, // A-labels lowercase
}

#[derive(Clone, Debug)]
pub struct LlmnrConflict {
    pub name: String,
    pub ifindex: i32,
    pub seen_from: SocketAddr,
}

pub struct LlmnrEngine {
    pub links: RwLock<Vec<LlmnrLinkCfg>>,
    pub conflicts: RwLock<Vec<LlmnrConflict>>,
    // Shared unicast resolver for "resolve" path when LLMNR lookup fails upward.
    // pub upstream: Arc<HyperResolver>,
}

impl LlmnrEngine {
    pub const PORT: u16 = 5355;
    pub const MCAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
    // FF02:0:0:0:0:0:1:3
    pub fn mcast_v6() -> Ipv6Addr {
        "ff02::1:3".parse().unwrap()
    }

    /// Join per-link multicast + bind 0.0.0.0:5355 / [::]:5355 with REUSEADDR/PORT.
    pub async fn run_udp(&self /* socks, router */) {
        // loop: recv_from → classify Query vs Response
        //  if Query && mode==Yes && we_own(name, ifindex) → respond unicast/multicast
        //  if Query && mode!=No && !we_own → optionally nothing (responder only for claims)
        //  if we issued query → match TXID+name, detect conflicts (two responders)
    }

    pub async fn query_name(
        &self,
        ifindex: i32,
        name: &str,
        qtype: u16,
    ) -> Result<Vec<std::net::IpAddr>, LlmnrErr> {
        // Build LLMNR query (QR=0, no RD recursion semantics like DNS)
        // Send to mcast on that interface only (IP_MULTICAST_IF / IPV6_MULTICAST_IF)
        // Collect unique answers within ~1s; conflict if contradictory A/AAAA
        // Return addresses with scope_id = ifindex for link-local
        let _ = (ifindex, name, qtype);
        Err(LlmnrErr::Timeout)
    }

    pub fn on_conflict(&self, c: LlmnrConflict) {
        // resolved: log + stop claiming name; optionally rename hostname policy
        self.conflicts.write().push(c);
    }
}

#[derive(Debug)]
pub enum LlmnrErr { Timeout, Disabled, Io(std::io::Error), Wire }
