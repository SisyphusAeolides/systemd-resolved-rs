// SPDX-License-Identifier: LGPL-2.1-or-later
mod resolvectl_rr;

use resolved::json::{self, Value};
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve";
const DEFAULT_MONITOR_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve.Monitor";
const MAX_REPLY_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
struct Options {
    socket: PathBuf,
    socket_explicit: bool,
    family: i32,
    command: String,
    arguments: Vec<String>,
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("resolvectl: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), Box<dyn Error>> {
    let Some(options) = parse_options()? else {
        return Ok(());
    };
    let monitor_socket = options.monitor_socket();
    match options.command.as_str() {
        "query" => query_many(&options.socket, &options.arguments, options.family),
        "openpgp" => resolvectl_rr::openpgp(&options.socket, &options.arguments),
        "tlsa" => resolvectl_rr::tlsa(&options.socket, &options.arguments),
        "status" => status(&options.socket),
        "statistics" => statistics(&monitor_socket),
        "show-cache" => show_cache(&monitor_socket),
        "show-server-state" => show_server_state(&monitor_socket),
        "flush-caches" => control(&options.socket, "io.systemd.Resolve.FlushCaches"),
        "reset-statistics" => control(
            &monitor_socket,
            "io.systemd.Resolve.Monitor.ResetStatistics",
        ),
        "reset-server-features" => {
            control(&options.socket, "io.systemd.Resolve.ResetServerFeatures")
        }
        command if resolved::resolvectl_dbus::is_command(command) => {
            resolved::resolvectl_dbus::execute(command, &options.arguments)
        }
        command => Err(format!("unknown command: {command}").into()),
    }
}

impl Options {
    fn monitor_socket(&self) -> PathBuf {
        if self.socket_explicit {
            monitor_socket_for(&self.socket)
        } else {
            PathBuf::from(DEFAULT_MONITOR_SOCKET)
        }
    }
}

fn monitor_socket_for(path: &Path) -> PathBuf {
    if path.file_name().and_then(|name| name.to_str()) == Some("io.systemd.Resolve") {
        return path.with_file_name("io.systemd.Resolve.Monitor");
    }
    let mut monitor = path.as_os_str().to_owned();
    monitor.push(".Monitor");
    PathBuf::from(monitor)
}

fn parse_options() -> Result<Option<Options>, Box<dyn Error>> {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut socket_explicit = false;
    let mut family = 0;
    let mut command = None;
    let mut command_arguments = Vec::new();
    let mut arguments = env::args().skip(1);

    while let Some(argument) = arguments.next() {
        if command.is_some() {
            command_arguments.push(argument);
            continue;
        }
        let (name, inline_value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value))
            });
        match name {
            "--socket" => {
                socket = option_value(inline_value, &mut arguments, name)?.into();
                socket_explicit = true;
            }
            "-4" => family = 2,
            "-6" => family = 10,
            "--version" => {
                println!("resolvectl {}", resolved::VERSION);
                return Ok(None);
            }
            "--help" | "-h" | "help" => {
                print_help();
                return Ok(None);
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown option: {argument}").into());
            }
            _ => command = Some(argument),
        }
    }

    let command = command.unwrap_or_else(|| "status".to_owned());
    if command == "query" && command_arguments.is_empty() {
        return Err("query requires at least one name or address".into());
    }
    Ok(Some(Options {
        socket,
        socket_explicit,
        family,
        command,
        arguments: command_arguments,
    }))
}

fn option_value(
    inline: Option<&str>,
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, Box<dyn Error>> {
    if let Some(value) = inline {
        if value.is_empty() {
            return Err(format!("{option} requires a value").into());
        }
        return Ok(value.to_owned());
    }
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value").into())
}

fn query_many(socket: &Path, inputs: &[String], family: i32) -> Result<(), Box<dyn Error>> {
    let mut failed = Vec::new();
    for input in inputs {
        if let Err(error) = query(socket, input, family) {
            eprintln!("{input}: {error}");
            failed.push(input.as_str());
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("{} query operation(s) failed", failed.len()).into())
    }
}

fn query(socket: &Path, input: &str, family: i32) -> Result<(), Box<dyn Error>> {
    let (method, parameters) = if let Ok(address) = input.parse::<IpAddr>() {
        let (address_family, bytes): (i32, Vec<u8>) = match address {
            IpAddr::V4(address) => (2, address.octets().to_vec()),
            IpAddr::V6(address) => (10, address.octets().to_vec()),
        };
        (
            "io.systemd.Resolve.ResolveAddress",
            Value::object([
                ("ifindex", Value::Number(0)),
                ("family", Value::Number(i128::from(address_family))),
                (
                    "address",
                    Value::Array(
                        bytes
                            .into_iter()
                            .map(|byte| Value::Number(i128::from(byte)))
                            .collect(),
                    ),
                ),
                ("flags", Value::Number(0)),
            ]),
        )
    } else {
        (
            "io.systemd.Resolve.ResolveHostname",
            Value::object([
                ("ifindex", Value::Number(0)),
                ("name", Value::String(input.to_owned())),
                ("family", Value::Number(i128::from(family))),
                ("flags", Value::Number(0)),
            ]),
        )
    };

    let reply = call(socket, method, parameters)?;
    let parameters = reply_parameters(&reply)?;
    let mut printed = false;

    if let Some(addresses) = parameters.get("addresses").and_then(Value::as_array) {
        for address in addresses {
            let family = address.get("family").and_then(Value::as_i64).unwrap_or(0);
            let bytes = byte_array(address.get("address"))?;
            let address = decode_address(family, &bytes)?;
            println!("{input}: {address}");
            printed = true;
        }
    }
    if let Some(names) = parameters.get("names").and_then(Value::as_array) {
        for name in names {
            if let Some(name) = name.get("name").and_then(Value::as_str) {
                println!("{input}: {name}");
                printed = true;
            }
        }
    }
    if !printed {
        return Err("reply contained no addresses or names".into());
    }
    Ok(())
}

fn byte_array(value: Option<&Value>) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("reply is missing an address byte array"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|number| u8::try_from(number).ok())
                .ok_or_else(|| invalid_data("reply contains an invalid address byte"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(bytes)
}

fn decode_address(family: i64, bytes: &[u8]) -> Result<IpAddr, Box<dyn Error>> {
    match (family, bytes) {
        (2, [a, b, c, d]) => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        (10, bytes) if bytes.len() == 16 => {
            let mut address = [0; 16];
            address.copy_from_slice(bytes);
            Ok(IpAddr::V6(Ipv6Addr::from(address)))
        }
        _ => Err("reply contains an invalid address family or size".into()),
    }
}

fn status(socket: &Path) -> Result<(), Box<dyn Error>> {
    let reply = call(
        socket,
        "org.varlink.service.GetInfo",
        Value::Object(BTreeMap::new()),
    )?;
    let parameters = reply_parameters(&reply)?;
    println!("Global");
    println!("       Protocol: Varlink");
    println!(
        "        Product: {}",
        parameters
            .get("product")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    );
    println!(
        "        Version: {}",
        parameters
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    );
    println!("         Socket: {}", socket.display());
    Ok(())
}

fn statistics(socket: &Path) -> Result<(), Box<dyn Error>> {
    let reply = call(
        socket,
        "io.systemd.Resolve.Monitor.DumpStatistics",
        Value::Object(BTreeMap::new()),
    )?;
    let parameters = reply_parameters(&reply)?;
    print_statistic_section(
        parameters,
        "transactions",
        "Transactions",
        &[
            ("Current Transactions", "currentTransactions"),
            ("Total Transactions", "totalTransactions"),
            ("Total Timeouts", "totalTimeouts"),
            ("Timeouts Served Stale", "totalTimeoutsServedStale"),
            ("Failed Responses", "totalFailedResponses"),
            (
                "Failed Responses Served Stale",
                "totalFailedResponsesServedStale",
            ),
        ],
    );
    print_statistic_section(
        parameters,
        "cache",
        "Cache",
        &[
            ("Current Cache Size", "size"),
            ("Cache Hits", "hits"),
            ("Cache Misses", "misses"),
        ],
    );
    print_statistic_section(
        parameters,
        "dnssec",
        "DNSSEC Verdicts",
        &[
            ("Secure", "secure"),
            ("Insecure", "insecure"),
            ("Bogus", "bogus"),
            ("Indeterminate", "indeterminate"),
        ],
    );
    Ok(())
}

fn print_statistic_section(parameters: &Value, field: &str, title: &str, entries: &[(&str, &str)]) {
    let Some(section) = parameters.get(field) else {
        return;
    };
    println!("{title}");
    for (label, key) in entries {
        if let Some(value) = section.get(key).and_then(Value::as_u64) {
            println!("  {label}: {value}");
        }
    }
}

fn show_cache(socket: &Path) -> Result<(), Box<dyn Error>> {
    let reply = call(
        socket,
        "io.systemd.Resolve.Monitor.DumpCache",
        Value::Object(BTreeMap::new()),
    )?;
    let scopes = reply_parameters(&reply)?
        .get("dump")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("cache dump is missing its scope array"))?;

    for (index, scope) in scopes.iter().enumerate() {
        if index != 0 {
            println!();
        }
        print_cache_scope(scope)?;
    }
    Ok(())
}

fn print_cache_scope(scope: &Value) -> Result<(), Box<dyn Error>> {
    let protocol = scope
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let ifname = scope.get("ifname").and_then(Value::as_str);
    let ifindex = scope.get("ifindex").and_then(Value::as_i64);
    match (ifname, ifindex) {
        (Some(name), Some(index)) => println!("Link {index} ({name}), protocol {protocol}"),
        (Some(name), None) => println!("Link {name}, protocol {protocol}"),
        (None, Some(index)) => println!("Link {index}, protocol {protocol}"),
        (None, None) => println!("Global, protocol {protocol}"),
    }

    let cache = scope
        .get("cache")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("cache scope is missing its entries"))?;
    if cache.is_empty() {
        println!("  Cache is empty");
        return Ok(());
    }

    for entry in cache {
        let key = entry
            .get("key")
            .ok_or_else(|| invalid_data("cache entry is missing its resource key"))?;
        let name = key.get("name").and_then(Value::as_str).unwrap_or("?");
        let class = key.get("class").and_then(Value::as_u64).unwrap_or(1);
        let rr_type = key.get("type").and_then(Value::as_u64).unwrap_or(0);
        print!(
            "  {name} {} {}",
            class_name(class),
            record_type_name(rr_type)
        );
        if let Some(kind) = entry.get("type").and_then(Value::as_str) {
            print!(" -- {kind}");
        } else if let Some(records) = entry.get("rrs").and_then(Value::as_array) {
            print!(
                " -- {} record{}",
                records.len(),
                if records.len() == 1 { "" } else { "s" }
            );
        }
        if let Some(until) = entry.get("until").and_then(Value::as_u64) {
            print!(" (valid until monotonic {until} µs)");
        }
        println!();
    }
    Ok(())
}

fn class_name(class: u64) -> String {
    match class {
        1 => "IN".to_owned(),
        255 => "ANY".to_owned(),
        other => format!("CLASS{other}"),
    }
}

fn record_type_name(rr_type: u64) -> String {
    match rr_type {
        1 => "A".to_owned(),
        2 => "NS".to_owned(),
        5 => "CNAME".to_owned(),
        6 => "SOA".to_owned(),
        12 => "PTR".to_owned(),
        15 => "MX".to_owned(),
        16 => "TXT".to_owned(),
        28 => "AAAA".to_owned(),
        33 => "SRV".to_owned(),
        43 => "DS".to_owned(),
        46 => "RRSIG".to_owned(),
        47 => "NSEC".to_owned(),
        48 => "DNSKEY".to_owned(),
        50 => "NSEC3".to_owned(),
        64 => "SVCB".to_owned(),
        65 => "HTTPS".to_owned(),
        255 => "ANY".to_owned(),
        other => format!("TYPE{other}"),
    }
}

fn show_server_state(socket: &Path) -> Result<(), Box<dyn Error>> {
    let reply = call(
        socket,
        "io.systemd.Resolve.Monitor.DumpServerState",
        Value::Object(BTreeMap::new()),
    )?;
    let servers = reply_parameters(&reply)?
        .get("dump")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("server-state dump is missing its array"))?;
    if servers.is_empty() {
        println!("No DNS servers are configured.");
        return Ok(());
    }

    for (index, server) in servers.iter().enumerate() {
        if index != 0 {
            println!();
        }
        print_server_state(server);
    }
    Ok(())
}

fn print_server_state(server: &Value) {
    let name = server
        .get("Server")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let kind = server
        .get("Type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    println!("Server {name} ({kind})");
    for (label, field) in [
        ("Interface", "Interface"),
        ("Interface Index", "InterfaceIndex"),
        ("Verified Feature Level", "VerifiedFeatureLevel"),
        ("Possible Feature Level", "PossibleFeatureLevel"),
        ("DNSSEC Mode", "DNSSECMode"),
        ("DNSSEC Supported", "DNSSECSupported"),
        ("Maximum UDP Fragment", "ReceivedUDPFragmentMax"),
        ("Failed UDP Attempts", "FailedUDPAttempts"),
        ("Failed TCP Attempts", "FailedTCPAttempts"),
        ("Packet Truncated", "PacketTruncated"),
        ("Bad OPT Record", "PacketBadOpt"),
        ("RRSIG Missing", "PacketRRSIGMissing"),
        ("Invalid Packet", "PacketInvalid"),
        ("DO Flag Dropped", "PacketDoOff"),
    ] {
        if let Some(value) = server.get(field).and_then(format_scalar) {
            println!("  {label}: {value}");
        }
    }
}

fn format_scalar(value: &Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        return Some(value.to_owned());
    }
    if let Some(value) = value.as_bool() {
        return Some(if value { "yes" } else { "no" }.to_owned());
    }
    if let Some(value) = value.as_i64() {
        return Some(value.to_string());
    }
    value.as_u64().map(|value| value.to_string())
}

fn control(socket: &Path, method: &str) -> Result<(), Box<dyn Error>> {
    let reply = call(socket, method, Value::Object(BTreeMap::new()))?;
    let _ = reply_parameters(&reply)?;
    Ok(())
}

fn call(socket: &Path, method: &str, parameters: Value) -> Result<Value, Box<dyn Error>> {
    let request = Value::object([
        ("method", Value::String(method.to_owned())),
        ("parameters", parameters),
    ]);
    let mut stream = UnixStream::connect(socket)?;
    stream.write_all(request.to_json().as_bytes())?;
    stream.write_all(&[0])?;

    let mut reply = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let length = stream.read(&mut chunk)?;
        if length == 0 {
            return Err("Varlink connection closed before a complete reply".into());
        }
        if let Some(position) = chunk[..length].iter().position(|byte| *byte == 0) {
            reply.extend_from_slice(&chunk[..position]);
            break;
        }
        reply.extend_from_slice(&chunk[..length]);
        if reply.len() > MAX_REPLY_SIZE {
            return Err("Varlink reply exceeds the configured limit".into());
        }
    }
    let text = std::str::from_utf8(&reply)?;
    Ok(json::parse(text)?)
}

fn reply_parameters(reply: &Value) -> Result<&Value, Box<dyn Error>> {
    if let Some(identifier) = reply.get("error").and_then(Value::as_str) {
        let detail = reply
            .get("parameters")
            .map(Value::to_json)
            .unwrap_or_default();
        if detail == "{}" || detail.is_empty() {
            return Err(identifier.to_owned().into());
        }
        return Err(format!("{identifier}: {detail}").into());
    }
    reply
        .get("parameters")
        .ok_or_else(|| "Varlink reply has no parameters".into())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn print_help() {
    println!(
        "resolvectl {}\n\
         Usage: resolvectl [--socket PATH] [-4|-6] COMMAND [ARGUMENTS]\n\
         Commands:\n\
           query NAME|ADDRESS...\n\
           openpgp EMAIL@DOMAIN...\n\
           tlsa [tcp|udp|sctp] DOMAIN[:PORT]...\n\
           status\n\
           statistics\n\
           show-cache\n\
           show-server-state\n\
           flush-caches\n\
           reset-statistics\n\
           reset-server-features\n\
           dns LINK [SERVER...]\n\
           domain LINK [DOMAIN...]\n\
           default-route LINK BOOL\n\
           llmnr LINK MODE\n\
           mdns LINK MODE\n\
           dnsovertls LINK MODE\n\
           dnssec LINK MODE\n\
           nta LINK [DOMAIN...]\n\
           revert LINK",
        resolved::VERSION
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_socket_tracks_default_and_custom_resolve_paths() {
        assert_eq!(
            monitor_socket_for(Path::new(DEFAULT_SOCKET)),
            PathBuf::from(DEFAULT_MONITOR_SOCKET)
        );
        assert_eq!(
            monitor_socket_for(Path::new("/tmp/resolved-test.sock")),
            PathBuf::from("/tmp/resolved-test.sock.Monitor")
        );
    }

    #[test]
    fn scalar_output_formats_strings_numbers_and_booleans() {
        assert_eq!(
            format_scalar(&Value::String("UDP".to_owned())).as_deref(),
            Some("UDP")
        );
        assert_eq!(format_scalar(&Value::Number(7)).as_deref(), Some("7"));
        assert_eq!(format_scalar(&Value::Bool(true)).as_deref(), Some("yes"));
    }
}
