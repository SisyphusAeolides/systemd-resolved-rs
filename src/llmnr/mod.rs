//! LLMNR RFC 4795 — resolve + respond skeleton wired for landing.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, warn};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmnrMode {
    No,
    Resolve,
    Yes,
}

#[derive(Clone, Debug)]
pub struct LlmnrLinkCfg {
    pub ifindex: i32,
    pub mode: LlmnrMode,
    pub claim_names: Vec<String>,
}

#[derive(Debug)]
pub struct LlmnrEngine {
    pub links: RwLock<Vec<LlmnrLinkCfg>>,
}

impl LlmnrEngine {
    pub const PORT: u16 = 5355;
    pub const MCAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);

    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            links: RwLock::new(Vec::new()),
        })
    }

    pub fn set_link(&self, cfg: LlmnrLinkCfg) {
        let mut g = self.links.write();
        if let Some(e) = g.iter_mut().find(|l| l.ifindex == cfg.ifindex) {
            *e = cfg;
        } else {
            g.push(cfg);
        }
    }

    pub fn we_own(&self, ifindex: i32, name: &str) -> bool {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        self.links.read().iter().any(|l| {
            l.ifindex == ifindex
                && l.mode == LlmnrMode::Yes
                && l.claim_names
                    .iter()
                    .any(|c| c.trim_end_matches('.').eq_ignore_ascii_case(&n))
        })
    }

    /// Spawn UDP listener — call from landing_glue.
    pub async fn run_udp(self: Arc<Self>, sock: tokio::net::UdpSocket) {
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "llmnr recv");
                    continue;
                }
            };
            if n < 12 {
                continue;
            }
            let qr = buf[2] & 0x80 != 0;
            if qr {
                continue; // response path for our queries later
            }
            // parse first question name (no compression expected often)
            if let Some(qname) = parse_qname(&buf[..n]) {
                debug!(%qname, %peer, "llmnr query");
                // ifindex unknown without IP_PKTINFO — use first Yes link as approx
                let links = self.links.read().clone();
                for l in links {
                    if l.mode == LlmnrMode::Yes && self.we_own(l.ifindex, &qname) {
                        if let Some(resp) = build_llmnr_response(&buf[..n], &[]) {
                            let _ = sock.send_to(&resp, peer).await;
                        }
                        break;
                    }
                }
            }
            let _ = SocketAddr::from(peer);
        }
    }
}

fn parse_qname(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 13 {
        return None;
    }
    let mut i = 12usize;
    let mut labels = Vec::new();
    loop {
        if i >= pkt.len() {
            return None;
        }
        let l = pkt[i] as usize;
        if l == 0 {
            break;
        }
        if l > 63 || i + 1 + l > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[i + 1..i + 1 + l]).to_string());
        i += 1 + l;
    }
    Some(labels.join("."))
}

fn build_llmnr_response(query: &[u8], addrs: &[[u8; 4]]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut r = query.to_vec();
    r[2] = 0x80; // QR
    r[3] = 0;
    // ancount
    let an = addrs.len() as u16;
    r[6] = (an >> 8) as u8;
    r[7] = an as u8;
    // append answers with compression pointer to qname 0xC00C
    for a in addrs {
        r.extend_from_slice(&[0xC0, 0x0C]); // name ptr
        r.extend_from_slice(&1u16.to_be_bytes()); // A
        r.extend_from_slice(&1u16.to_be_bytes()); // IN
        r.extend_from_slice(&30u32.to_be_bytes()); // ttl
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(a);
    }
    Some(r)
}
