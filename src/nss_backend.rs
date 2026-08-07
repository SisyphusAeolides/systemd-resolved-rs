//! Server-side helpers for nss-resolve miss path (varlink / internal API).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct NssHostnameResult {
    pub canonical: String,
    pub addrs: Vec<NssAddr>,
    pub ttl: u32,
    pub secure: bool,
}

#[derive(Clone, Debug)]
pub struct NssAddr {
    pub ip: IpAddr,
    pub ifindex: i32,
}

#[derive(Clone, Debug)]
pub struct NssReverseResult {
    pub names: Vec<String>,
    pub ttl: u32,
}

/// Encode presentation name → lowercase absolute wire (no compression).
pub fn name_to_wire_lower(name: &str) -> Result<Vec<u8>, &'static str> {
    let n = name.trim().trim_end_matches('.');
    if n.is_empty() {
        return Ok(vec![0]);
    }
    let mut out = Vec::with_capacity(n.len() + 2);
    for lab in n.split('.') {
        if lab.is_empty() || lab.len() > 63 {
            return Err("bad label");
        }
        out.push(lab.len() as u8);
        for b in lab.bytes() {
            out.push(if (b'A'..=b'Z').contains(&b) { b + 32 } else { b });
        }
    }
    out.push(0);
    if out.len() > 255 {
        return Err("too long");
    }
    Ok(out)
}

pub fn wire_to_presentation(wire: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0usize;
    while i < wire.len() {
        let l = wire[i] as usize;
        if l == 0 {
            break;
        }
        if !s.is_empty() {
            s.push('.');
        }
        if i + 1 + l > wire.len() {
            break;
        }
        s.push_str(&String::from_utf8_lossy(&wire[i + 1..i + 1 + l]));
        i += 1 + l;
    }
    if s.is_empty() {
        ".".into()
    } else {
        s
    }
}

/// Build SHM address records from resolver answer IPs.
pub fn ips_to_shm_style(addrs: &[(IpAddr, i32)]) -> Vec<(u8, u16, [u8; 16])> {
    let mut out = Vec::new();
    for (ip, ifi) in addrs {
        match ip {
            IpAddr::V4(v4) => {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&v4.octets());
                out.push((4u8, *ifi as u16, a));
            }
            IpAddr::V6(v6) => {
                out.push((6u8, *ifi as u16, v6.octets()));
            }
        }
    }
    out
}

pub fn parse_v4(s: &str) -> Option<Ipv4Addr> {
    s.parse().ok()
}
pub fn parse_v6(s: &str) -> Option<Ipv6Addr> {
    s.parse().ok()
}
