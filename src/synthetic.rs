//! localhost, hostname, gateway, _gateway, _outbound, reverse zonals, etc.
#![allow(missing_debug_implementations)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub enum SynthAnswer {
    Addrs(Vec<IpAddr>),
    Name(String),
    NxDomain,
    NoData,
}

pub struct SynthContext<'a> {
    pub hostname: &'a str, // from /etc/hostname / LLMNRHostname
    pub pretty_hostname: Option<&'a str>,
    pub gateway_v4: Option<Ipv4Addr>,
    pub gateway_v6: Option<Ipv6Addr>,
    pub local_addrs: &'a [(i32, IpAddr)], // ifindex, addr
    pub hosts_file: &'a HostsDB,
}

pub fn lookup_synthetic(ctx: &SynthContext, qname: &str, qtype: u16) -> Option<SynthAnswer> {
    let n = qname.trim_end_matches('.').to_ascii_lowercase();
    match n.as_str() {
        "localhost" | "localhost.localdomain" => {
            if qtype == 1 {
                return Some(SynthAnswer::Addrs(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]));
            }
            if qtype == 28 {
                return Some(SynthAnswer::Addrs(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]));
            }
        }
        "_gateway" | "gateway" => {
            let mut v = vec![];
            if let Some(a) = ctx.gateway_v4 {
                v.push(IpAddr::V4(a));
            }
            if let Some(a) = ctx.gateway_v6 {
                v.push(IpAddr::V6(a));
            }
            if !v.is_empty() {
                return Some(SynthAnswer::Addrs(v));
            }
        }
        "_outbound" => { /* primary outbound iface addr — networkd/route */ }
        x if x == ctx.hostname || ctx.pretty_hostname == Some(x) => {
            let addrs: Vec<_> = ctx.local_addrs.iter().map(|(_, a)| *a).collect();
            if !addrs.is_empty() {
                return Some(SynthAnswer::Addrs(addrs));
            }
        }
        _ => {}
    }
    // 127.0.0.0/8 PTR → localhost
    // hosts_file hit
    ctx.hosts_file.lookup(&n, qtype)
}

pub struct HostsDB;
impl HostsDB {
    pub fn lookup(&self, _n: &str, _t: u16) -> Option<SynthAnswer> {
        None
    }
}
