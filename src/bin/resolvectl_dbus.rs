// SPDX-License-Identifier: LGPL-2.1-or-later
use resolved::config::parse_server_spec;
use std::error::Error;
use std::fs;
use std::net::IpAddr;
use zbus::blocking::{Connection, Proxy};

const BUS_NAME: &str = "org.freedesktop.resolve1";
const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
const MANAGER_INTERFACE: &str = "org.freedesktop.resolve1.Manager";

pub fn is_command(command: &str) -> bool {
    matches!(
        command,
        "dns"
            | "domain"
            | "default-route"
            | "llmnr"
            | "mdns"
            | "dnsovertls"
            | "dnssec"
            | "nta"
            | "revert"
    )
}

pub fn execute(command: &str, arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let connection = Connection::system()?;
    let proxy = Proxy::new(
        &connection,
        BUS_NAME,
        MANAGER_PATH,
        MANAGER_INTERFACE,
    )?;

    match command {
        "dns" => set_dns(&proxy, arguments),
        "domain" => set_domains(&proxy, arguments),
        "default-route" => set_default_route(&proxy, arguments),
        "llmnr" => set_mode(&proxy, "SetLinkLLMNR", arguments),
        "mdns" => set_mode(&proxy, "SetLinkMulticastDNS", arguments),
        "dnsovertls" => set_mode(&proxy, "SetLinkDNSOverTLS", arguments),
        "dnssec" => set_mode(&proxy, "SetLinkDNSSEC", arguments),
        "nta" => set_negative_trust_anchors(&proxy, arguments),
        "revert" => revert(&proxy, arguments),
        _ => Err(format!("unsupported D-Bus command: {command}").into()),
    }
}

fn set_dns(proxy: &Proxy<'_>, arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let (link, values) = link_and_values("dns", arguments)?;
    let mut servers = Vec::with_capacity(values.len());
    for value in values {
        let spec = parse_server_spec(value)?;
        if let Some(interface) = &spec.interface {
            let specified = parse_ifindex(interface)?;
            if specified != link {
                return Err(format!(
                    "DNS server {value} is scoped to interface {specified}, not {link}"
                )
                .into());
            }
        }
        let (family, bytes) = encode_address(spec.address.ip());
        servers.push((
            family,
            bytes,
            spec.address.port(),
            spec.server_name.unwrap_or_default(),
        ));
    }
    let _: () = proxy.call("SetLinkDNSEx", &(link, servers))?;
    Ok(())
}

fn set_domains(proxy: &Proxy<'_>, arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let (link, values) = link_and_values("domain", arguments)?;
    let mut domains = Vec::with_capacity(values.len());
    for value in values {
        let (route_only, name) = value
            .strip_prefix('~')
            .map_or((false, value.as_str()), |name| (true, name));
        let name = name.trim_end_matches('.');
        if name.is_empty() {
            return Err(format!("invalid domain: {value}").into());
        }
        domains.push((name.to_owned(), route_only));
    }
    let _: () = proxy.call("SetLinkDomains", &(link, domains))?;
    Ok(())
}

fn set_default_route(proxy: &Proxy<'_>, arguments: &[String]) -> Result<(), Box<dyn Error>> {
    require_exact("default-route", arguments, 2)?;
    let link = parse_ifindex(&arguments[0])?;
    let enabled = parse_boolean(&arguments[1])?;
    let _: () = proxy.call("SetLinkDefaultRoute", &(link, enabled))?;
    Ok(())
}

fn set_mode(
    proxy: &Proxy<'_>,
    method: &str,
    arguments: &[String],
) -> Result<(), Box<dyn Error>> {
    require_exact(method, arguments, 2)?;
    let link = parse_ifindex(&arguments[0])?;
    let mode = arguments[1].as_str();
    let _: () = proxy.call(method, &(link, mode))?;
    Ok(())
}

fn set_negative_trust_anchors(
    proxy: &Proxy<'_>,
    arguments: &[String],
) -> Result<(), Box<dyn Error>> {
    let (link, values) = link_and_values("nta", arguments)?;
    let names = values
        .iter()
        .map(|name| name.trim_end_matches('.'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if names.iter().any(String::is_empty) {
        return Err("negative trust anchors must not be empty".into());
    }
    let _: () = proxy.call("SetLinkDNSSECNegativeTrustAnchors", &(link, names))?;
    Ok(())
}

fn revert(proxy: &Proxy<'_>, arguments: &[String]) -> Result<(), Box<dyn Error>> {
    require_exact("revert", arguments, 1)?;
    let link = parse_ifindex(&arguments[0])?;
    let _: () = proxy.call("RevertLink", &(link,))?;
    Ok(())
}

fn link_and_values<'a>(
    command: &str,
    arguments: &'a [String],
) -> Result<(i32, &'a [String]), Box<dyn Error>> {
    let Some((link, values)) = arguments.split_first() else {
        return Err(format!("{command} requires a link").into());
    };
    Ok((parse_ifindex(link)?, values))
}

fn require_exact(command: &str, arguments: &[String], expected: usize) -> Result<(), Box<dyn Error>> {
    if arguments.len() != expected {
        return Err(format!(
            "{command} requires {expected} argument{}",
            if expected == 1 { "" } else { "s" }
        )
        .into());
    }
    Ok(())
}

fn parse_ifindex(value: &str) -> Result<i32, Box<dyn Error>> {
    if let Ok(index) = value.parse::<i32>() {
        if index > 0 {
            return Ok(index);
        }
        return Err(format!("invalid interface index: {value}").into());
    }
    if value.is_empty()
        || value.len() > 15
        || value.contains('/')
        || value.chars().any(char::is_whitespace)
    {
        return Err(format!("invalid interface name: {value}").into());
    }
    let index = fs::read_to_string(format!("/sys/class/net/{value}/ifindex"))?;
    let index = index.trim().parse::<i32>()?;
    if index <= 0 {
        return Err(format!("invalid interface index for {value}: {index}").into());
    }
    Ok(index)
}

fn parse_boolean(value: &str) -> Result<bool, Box<dyn Error>> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        _ => Err(format!("invalid boolean value: {value}").into()),
    }
}

fn encode_address(address: IpAddr) -> (i32, Vec<u8>) {
    match address {
        IpAddr::V4(address) => (2, address.octets().to_vec()),
        IpAddr::V6(address) => (10, address.octets().to_vec()),
    }
}
