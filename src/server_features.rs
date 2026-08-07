//! src/server_features.rs
#![allow(missing_debug_implementations)]

#[derive(Clone, Debug, Default)]
pub struct ServerFeatures {
    pub edns: Option<bool>,
    pub do_bit_ok: Option<bool>,
    pub udp_payload: u16,
    pub dnssec_validated_ok: Option<bool>,
    pub tcp_required: bool,
    pub dot_ok: Option<bool>,
    pub cookie_ok: Option<bool>,
    pub last_probe: Option<std::time::Instant>,
}

pub struct Upstream;
pub trait Transport {}

pub async fn probe_server(up: &Upstream, t: &dyn Transport) -> ServerFeatures {
    // 1) small query with OPT DO
    // 2) if FORMERR → edns=false
    // 3) if TC → tcp_required / lower payload
    // 4) if DoT mode opportunistic: try TLS 853, fall back
    // 5) store in map hashed by ServerIdentity (addr|port|ifindex|sni)
    let _ = (up, t);
    ServerFeatures { udp_payload: 1232, ..Default::default() }
}
