// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::daemon::stop_requested;
use crate::json::{self, Value};
use crate::native;
use crate::resolver::{ResolveError, Resolver};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const INTERFACE_DESCRIPTION: &str = "interface io.systemd.Resolve\n\
method ResolveHostname(ifindex: ?int, name: string, family: ?int, flags: ?int) -> (addresses: [](ifindex: ?int, family: int, address: []int), name: string, flags: int)\n\
method ResolveAddress(ifindex: ?int, family: int, address: []int, flags: ?int) -> (names: [](ifindex: ?int, name: string), flags: int)\n\
method ResolveRecord(ifindex: ?int, name: string, class: ?int, type: int, flags: ?int) -> (rrs: [](ifindex: ?int, rr: ?object, raw: string), flags: int)";

#[derive(Debug)]
pub struct VarlinkServer {
    path: PathBuf,
    resolver: Arc<Resolver>,
}

impl VarlinkServer {
    pub fn new(path: impl Into<PathBuf>, resolver: Arc<Resolver>) -> Self {
        Self {
            path: path.into(),
            resolver,
        }
    }

    pub fn run(&self) -> io::Result<()> {
        prepare_socket_path(&self.path)?;
        let listener = UnixListener::bind(&self.path)?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o666))?;
        listener.set_nonblocking(true)?;
        while !stop_requested() {
            match listener.accept() {
                Ok((stream, _)) => {
                    let resolver = Arc::clone(&self.resolver);
                    let _ = thread::Builder::new()
                        .name("resolved-varlink-client".to_owned())
                        .spawn(move || {
                            if let Err(error) = serve_connection(stream, resolver) {
                                eprintln!("systemd-resolved: Varlink connection failed: {error}");
                            }
                        });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        let _ = fs::remove_file(&self.path);
        Ok(())
    }
}

fn prepare_socket_path(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "refusing to replace a non-socket Varlink path",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn serve_connection(mut stream: UnixStream, resolver: Arc<Resolver>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let can_control = native::peer_credentials(stream.as_raw_fd())
        .map(|credentials| credentials.uid == 0)
        .unwrap_or(false);
    let mut pending = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        if let Some(end) = pending.iter().position(|byte| *byte == 0) {
            let message: Vec<_> = pending.drain(..=end).collect();
            let reply = match std::str::from_utf8(&message[..message.len() - 1]) {
                Ok(text) => dispatch_with_access(text, &resolver, can_control),
                Err(_) => invalid_parameter("message"),
            };
            stream.write_all(reply.to_json().as_bytes())?;
            stream.write_all(&[0])?;
            continue;
        }

        let length = stream.read(&mut chunk)?;
        if length == 0 {
            return Ok(());
        }
        pending.extend_from_slice(&chunk[..length]);
        if pending.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varlink message is too large",
            ));
        }
    }
}

pub fn dispatch(input: &str, resolver: &Resolver) -> Value {
    dispatch_with_access(input, resolver, false)
}

fn dispatch_with_access(input: &str, resolver: &Resolver, can_control: bool) -> Value {
    let request = match json::parse(input) {
        Ok(value) => value,
        Err(_) => return invalid_parameter("message"),
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return invalid_parameter("method");
    };
    let parameters = request
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| Value::Object(BTreeMap::new()));

    match method {
        "org.varlink.service.GetInfo" => success(Value::object([
            ("vendor", Value::String("SisyphusAeolides".to_owned())),
            ("product", Value::String("systemd-resolved-rs".to_owned())),
            ("version", Value::String(crate::VERSION.to_owned())),
            (
                "url",
                Value::String("https://github.com/SisyphusAeolides/systemd-resolved-rs".to_owned()),
            ),
            (
                "interfaces",
                Value::Array(vec![
                    Value::String("io.systemd.Resolve".to_owned()),
                    Value::String("org.varlink.service".to_owned()),
                ]),
            ),
        ])),
        "org.varlink.service.GetInterfaceDescription" => {
            if parameters.get("interface").and_then(Value::as_str) == Some("io.systemd.Resolve") {
                success(Value::object([(
                    "description",
                    Value::String(INTERFACE_DESCRIPTION.to_owned()),
                )]))
            } else {
                error("org.varlink.service.InterfaceNotFound")
            }
        }
        "io.systemd.Resolve.ResolveHostname" => resolve_hostname(&parameters, resolver),
        "io.systemd.Resolve.ResolveAddress" => resolve_address(&parameters, resolver),
        "io.systemd.Resolve.ResolveRecord" => error("org.varlink.service.MethodNotImplemented"),
        "io.systemd.Resolve.ResolveService" => error("org.varlink.service.MethodNotImplemented"),
        "io.systemd.Resolve.FlushCaches" => control(can_control, || resolver.flush_cache()),
        "io.systemd.Resolve.ResetServerFeatures" => {
            control(can_control, || resolver.reset_server_features())
        }
        "io.systemd.Resolve.ResetStatistics" => {
            control(can_control, || resolver.reset_statistics())
        }
        "io.systemd.Resolve.GetStatistics" => statistics(resolver),
        _ => error("org.varlink.service.MethodNotFound"),
    }
}

fn resolve_hostname(parameters: &Value, resolver: &Resolver) -> Value {
    let Some(name) = parameters.get("name").and_then(Value::as_str) else {
        return invalid_parameter("name");
    };
    let family = match optional_i32(parameters, "family", 0) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let ifindex = match optional_i32(parameters, "ifindex", 0) {
        Ok(value) => value,
        Err(error) => return error,
    };

    match resolver.lookup_name(name, family) {
        Ok(result) => {
            let addresses = result
                .addresses
                .into_iter()
                .map(|address| {
                    let (family, bytes): (i32, Vec<u8>) = match address {
                        IpAddr::V4(address) => (2, address.octets().to_vec()),
                        IpAddr::V6(address) => (10, address.octets().to_vec()),
                    };
                    Value::object([
                        ("ifindex", Value::Number(i128::from(ifindex))),
                        ("family", Value::Number(i128::from(family))),
                        (
                            "address",
                            Value::Array(
                                bytes
                                    .into_iter()
                                    .map(|byte| Value::Number(i128::from(byte)))
                                    .collect(),
                            ),
                        ),
                    ])
                })
                .collect();
            success(Value::object([
                ("addresses", Value::Array(addresses)),
                ("name", Value::String(result.canonical_name)),
                ("flags", Value::Number(i128::from(result.flags))),
            ]))
        }
        Err(error) => resolver_error(error),
    }
}

fn resolve_address(parameters: &Value, resolver: &Resolver) -> Value {
    let Some(values) = parameters.get("address").and_then(Value::as_array) else {
        return invalid_parameter("address");
    };
    let family = match required_i32(parameters, "family") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let ifindex = match optional_i32(parameters, "ifindex", 0) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Some(octets) = values
        .iter()
        .map(|value| value.as_u64().and_then(|number| u8::try_from(number).ok()))
        .collect::<Option<Vec<_>>>()
    else {
        return invalid_parameter("address");
    };
    let address = match (family, octets.as_slice()) {
        (2, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        (10, bytes) if bytes.len() == 16 => {
            let mut address = [0; 16];
            address.copy_from_slice(bytes);
            IpAddr::V6(Ipv6Addr::from(address))
        }
        _ => return error("io.systemd.Resolve.BadAddressSize"),
    };

    match resolver.lookup_address(address) {
        Ok(result) => success(Value::object([
            (
                "names",
                Value::Array(
                    result
                        .names
                        .into_iter()
                        .map(|name| {
                            Value::object([
                                ("ifindex", Value::Number(i128::from(ifindex))),
                                ("name", Value::String(name)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("flags", Value::Number(i128::from(result.flags))),
        ])),
        Err(error) => resolver_error(error),
    }
}

fn control(can_control: bool, operation: impl FnOnce()) -> Value {
    if !can_control {
        return error("org.varlink.service.PermissionDenied");
    }
    operation();
    success(Value::Object(BTreeMap::new()))
}

fn statistics(resolver: &Resolver) -> Value {
    let statistics = resolver.stats();
    success(Value::object([
        (
            "transactions",
            Value::Number(i128::from(statistics.transactions)),
        ),
        (
            "cacheHits",
            Value::Number(i128::from(statistics.cache_hits)),
        ),
        (
            "cacheMisses",
            Value::Number(i128::from(statistics.cache_misses)),
        ),
        ("failures", Value::Number(i128::from(statistics.failures))),
        (
            "localAnswers",
            Value::Number(i128::from(statistics.local_answers)),
        ),
        (
            "cacheEntries",
            Value::Number(i128::try_from(statistics.cache_entries).unwrap_or(i128::MAX)),
        ),
    ]))
}

fn required_i32(parameters: &Value, key: &str) -> Result<i32, Value> {
    parameters
        .get(key)
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| invalid_parameter(key))
}

fn optional_i32(parameters: &Value, key: &str, default: i32) -> Result<i32, Value> {
    match parameters.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| invalid_parameter(key)),
    }
}

fn resolver_error(error_value: ResolveError) -> Value {
    error(error_value.varlink_id())
}

fn success(parameters: Value) -> Value {
    Value::object([("parameters", parameters)])
}

fn error(identifier: &str) -> Value {
    Value::object([
        ("error", Value::String(identifier.to_owned())),
        ("parameters", Value::Object(BTreeMap::new())),
    ])
}

fn invalid_parameter(parameter: &str) -> Value {
    Value::object([
        (
            "error",
            Value::String("org.varlink.service.InvalidParameter".to_owned()),
        ),
        (
            "parameters",
            Value::object([("parameter", Value::String(parameter.to_owned()))]),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn maintenance_call_requires_privileged_peer() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"io.systemd.Resolve.FlushCaches","parameters":{}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("org.varlink.service.PermissionDenied")
        );
    }

    #[test]
    fn get_info_lists_resolve_interface() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"org.varlink.service.GetInfo","parameters":{}}"#,
            &resolver,
        );
        let interfaces = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("interfaces"))
            .and_then(Value::as_array)
            .expect("interfaces");
        assert!(interfaces
            .iter()
            .any(|value| value.as_str() == Some("io.systemd.Resolve")));
    }
}
