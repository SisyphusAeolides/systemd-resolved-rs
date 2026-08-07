//! Synthetic answers: localhost, hostname, _gateway, hosts file.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub enum SynthAnswer {
    Addrs(Vec<IpAddr>),
    NxDomain,
    NoData,
}

#[derive(Debug)]
pub struct SynthContext<'a> {
    pub hostname: &'a str,
    pub pretty_hostname: Option<&'a str>,
    pub gateway_v4: Option<Ipv4Addr>,
    pub gateway_v6: Option<Ipv6Addr>,
    pub local_addrs: &'a [IpAddr],
}

pub fn lookup_synthetic(ctx: &SynthContext<'_>, qname: &str, qtype: u16) -> Option<SynthAnswer> {
    let n = qname.trim_end_matches('.').to_ascii_lowercase();

    if n == "localhost" || n == "localhost.localdomain" {
        return match qtype {
            1 => Some(SynthAnswer::Addrs(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])),
            28 => Some(SynthAnswer::Addrs(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)])),
            255 => Some(SynthAnswer::Addrs(vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ])),
            _ => Some(SynthAnswer::NoData),
        };
    }

    if n == "_gateway" || n == "gateway" {
        let mut v = Vec::new();
        if matches!(qtype, 1 | 255) {
            if let Some(a) = ctx.gateway_v4 {
                v.push(IpAddr::V4(a));
            }
        }
        if matches!(qtype, 28 | 255) {
            if let Some(a) = ctx.gateway_v6 {
                v.push(IpAddr::V6(a));
            }
        }
        if !v.is_empty() {
            return Some(SynthAnswer::Addrs(v));
        }
        return Some(SynthAnswer::NxDomain);
    }

    let host = ctx.hostname.trim_end_matches('.').to_ascii_lowercase();
    let pretty = ctx
        .pretty_hostname
        .map(|p| p.trim_end_matches('.').to_ascii_lowercase());
    if n == host || pretty.as_deref() == Some(n.as_str()) {
        let mut v = Vec::new();
        for a in ctx.local_addrs {
            match (qtype, a) {
                (1, IpAddr::V4(_)) | (28, IpAddr::V6(_)) | (255, _) => v.push(*a),
                _ => {}
            }
        }
        if !v.is_empty() {
            return Some(SynthAnswer::Addrs(v));
        }
    }

    None
}

/// PTR for 127.0.0.0/8 and ::1
pub fn lookup_synthetic_ptr(addr: IpAddr) -> Option<String> {
    match addr {
        IpAddr::V4(v) if v.octets()[0] == 127 => Some("localhost".into()),
        IpAddr::V6(v) if v.is_loopback() => Some("localhost".into()),
        _ => None,
    }
}
