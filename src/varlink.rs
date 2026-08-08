// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::daemon::stop_requested;
use crate::json::{self, Value};
use crate::native;
use crate::resolver::{ResolveError, Resolver};
use crate::wire::{
    extract_answer_records, extract_service_records, make_query, Header, CLASS_ANY, CLASS_IN,
    TYPE_A, TYPE_AAAA, TYPE_SRV, TYPE_TXT,
};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const SD_RESOLVED_NO_TXT: u64 = 1 << 6;
const SD_RESOLVED_NO_ADDRESS: u64 = 1 << 7;
const INTERFACE_DESCRIPTION: &str = "interface io.systemd.Resolve\n\
method ResolveHostname(ifindex: ?int, name: string, family: ?int, flags: ?int) -> (addresses: [](ifindex: ?int, family: int, address: []int), name: string, flags: int)\n\
method ResolveAddress(ifindex: ?int, family: int, address: []int, flags: ?int) -> (names: [](ifindex: ?int, name: string), flags: int)\n\
method ResolveService(name: ?string, type: ?string, domain: string, ifindex: ?int, family: ?int, flags: ?int) -> (services: [](priority: int, weight: int, port: int, hostname: string, canonicalName: ?string, addresses: ?[](ifindex: ?int, family: int, address: []int)), txt: ?[]string, canonical: (name: ?string, type: string, domain: string), flags: int)\n\
method ResolveRecord(ifindex: ?int, name: string, class: ?int, type: int, flags: ?int) -> (rrs: [](ifindex: ?int, rr: ?object, raw: string), flags: int)\n\
type DNSServer (address: []int, addressString: string, family: int, port: int, ifindex: ?int, name: ?string, accessible: ?bool)\n\
type SearchDomain (name: string, routeOnly: bool, ifindex: ?int)\n\
type DNSConfiguration (ifname: ?string, ifindex: ?int, delegate: ?string, defaultRoute: ?bool, currentServer: ?DNSServer, servers: ?[]DNSServer, fallbackServers: ?[]DNSServer, searchDomains: ?[]SearchDomain, negativeTrustAnchors: ?[]string, dnssec: ?string, dnssecSupported: ?bool, dnsOverTLS: ?string, llmnr: ?string, mDNS: ?string, resolvConfMode: ?string, scopes: ?[]string)\n\
method DumpDNSConfiguration() -> (configuration: []DNSConfiguration)\n\
error QueryAborted\n\
error QueryRefused\n\
error DNSSECValidationFailed(result: string, extendedDNSErrorCode: ?int, extendedDNSErrorMessage: ?string)\n\
error NoTrustAnchor\n\
error StubLoop\n\
error ResourceRecordTypeObsolete\n\
error InconsistentServiceRecords";

#[derive(Debug)]
pub struct VarlinkServer {
    path: PathBuf,
    resolver: Arc<Resolver>,
    activated_listener: Option<UnixListener>,
}

impl VarlinkServer {
    pub fn new(path: impl Into<PathBuf>, resolver: Arc<Resolver>) -> io::Result<Self> {
        let activated_listener = take_activated_listener()?;
        Ok(Self {
            path: path.into(),
            resolver,
            activated_listener,
        })
    }

    pub fn run(&self) -> io::Result<()> {
        let (listener, remove_path) = if let Some(listener) = &self.activated_listener {
            (listener.try_clone()?, false)
        } else {
            prepare_socket_path(&self.path)?;
            let listener = UnixListener::bind(&self.path)?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o666))?;
            (listener, true)
        };
        listener.set_nonblocking(true)?;
        while !stop_requested() {
            match listener.accept() {
                Ok((stream, _)) => {
                    let resolver = Arc::clone(&self.resolver);
                    let _ = thread::Builder::new()
                        .name("resolved-varlink-client".to_owned())
                        .spawn(move || {
                            if let Err(error) = serve_connection(stream, &resolver) {
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
        if remove_path {
            let _ = fs::remove_file(&self.path);
        }
        Ok(())
    }
}

fn take_activated_listener() -> io::Result<Option<UnixListener>> {
    let names = env::var("LISTEN_FDNAMES").ok();
    let count = native::listen_fds()?;
    let Some(fd) = activated_varlink_fd(count, names.as_deref())? else {
        return Ok(None);
    };

    // SAFETY: systemd activation descriptors start at 3; activated_varlink_fd validates
    // that exactly one descriptor was supplied for this process before ownership moves here.
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    let _ = listener.local_addr()?;
    Ok(Some(listener))
}

fn activated_varlink_fd(count: usize, names: Option<&str>) -> io::Result<Option<RawFd>> {
    if count == 0 {
        return Ok(None);
    }
    if count != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected exactly one activated Varlink descriptor",
        ));
    }
    if matches!(names, Some(name) if !name.is_empty() && name != "varlink") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "activated descriptor is not named varlink",
        ));
    }
    Ok(Some(3))
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

fn serve_connection(mut stream: UnixStream, resolver: &Resolver) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let can_control = matches!(
        native::peer_credentials(stream.as_raw_fd()),
        Ok(credentials) if credentials.uid == 0
    );
    let mut pending = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        if let Some(end) = pending.iter().position(|byte| *byte == 0) {
            let message: Vec<_> = pending.drain(..=end).collect();
            let reply = match std::str::from_utf8(&message[..message.len() - 1]) {
                Ok(text) => dispatch_with_access(text, resolver, can_control),
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
    let Ok(request) = json::parse(input) else {
        return invalid_parameter("message");
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
        "io.systemd.Resolve.ResolveRecord" => resolve_record(&parameters, resolver),
        "io.systemd.Resolve.ResolveService" => resolve_service(&parameters, resolver),
        "io.systemd.Resolve.DumpDNSConfiguration" => dump_dns_configuration(resolver),
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

include!("varlink_dns_configuration.rs");

fn resolve_hostname(parameters: &Value, resolver: &Resolver) -> Value {
    let Some(name) = parameters.get("name").and_then(Value::as_str) else {
        return invalid_parameter("name");
    };
    let family = match optional_i32(parameters, "family", 0) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let ifindex = match optional_i32(parameters, "ifindex", 0) {
        Ok(value) if value >= 0 => value,
        Ok(_) => return invalid_parameter("ifindex"),
        Err(error) => return error,
    };

    match resolver.lookup_name_on_link(name, family, (ifindex > 0).then_some(ifindex)) {
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
        Err(error) => resolver_error(&error),
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
        Ok(value) if value >= 0 => value,
        Ok(_) => return invalid_parameter("ifindex"),
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

    match resolver.lookup_address_on_link(address, (ifindex > 0).then_some(ifindex)) {
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
        Err(error) => resolver_error(&error),
    }
}

#[derive(Debug)]
struct ServiceQuestion {
    owner: String,
    name: Option<String>,
    service_type: String,
    domain: String,
}

#[derive(Debug)]
struct ServiceRequest {
    question: ServiceQuestion,
    family: i32,
    ifindex: i32,
    flags: u64,
}

#[derive(Debug)]
struct ServiceEntries {
    values: Vec<Value>,
    root_target: bool,
    last_address_error: Option<ResolveError>,
}

fn resolve_service(parameters: &Value, resolver: &Resolver) -> Value {
    let mut request = match service_request(parameters) {
        Ok(request) => request,
        Err(error) => return error,
    };
    apply_refused_service_flags(&mut request, resolver);
    let srv_response = match resolver.resolve_record_on_link(
        &request.question.owner,
        CLASS_IN,
        TYPE_SRV,
        (request.ifindex > 0).then_some(request.ifindex),
    ) {
        Ok(response) => response,
        Err(error) => return resolver_error(&error),
    };
    let Ok(records) = extract_service_records(&srv_response) else {
        return error("io.systemd.Resolve.InvalidReply");
    };
    let entries = resolve_service_entries(records, resolver, &request);
    if entries.values.is_empty() {
        if entries.root_target {
            return error("io.systemd.Resolve.ServiceNotProvided");
        }
        if let Some(address_error) = entries.last_address_error {
            return resolver_error(&address_error);
        }
        return error("io.systemd.Resolve.NoSuchResourceRecord");
    }

    let mut output = service_parameters(
        &request.question,
        entries.values,
        &srv_response,
        request.flags,
    );
    if let Err(error) = add_service_txt(&mut output, &request, resolver) {
        return error;
    }
    success(Value::Object(output))
}

fn apply_refused_service_flags(request: &mut ServiceRequest, resolver: &Resolver) {
    let refused = &resolver.config().refuse_record_types;
    if refused.contains(&TYPE_A) && refused.contains(&TYPE_AAAA) {
        request.flags |= SD_RESOLVED_NO_ADDRESS;
    }
    if refused.contains(&TYPE_TXT) {
        request.flags |= SD_RESOLVED_NO_TXT;
    }
}

fn service_request(parameters: &Value) -> Result<ServiceRequest, Value> {
    let name = optional_string(parameters, "name")?;
    let service_type = optional_string(parameters, "type")?;
    let domain = parameters
        .get("domain")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_parameter("domain"))?;
    let family @ (0 | 2 | 10) = optional_i32(parameters, "family", 0)? else {
        return Err(invalid_parameter("family"));
    };
    let ifindex = optional_i32(parameters, "ifindex", 0)?;
    if ifindex < 0 {
        return Err(invalid_parameter("ifindex"));
    }
    let flags = optional_u64(parameters, "flags", 0)?;
    if name
        .as_deref()
        .is_some_and(|value| !service_instance_is_valid(value))
    {
        return Err(invalid_parameter("name"));
    }
    if service_type
        .as_deref()
        .is_some_and(|value| !service_type_is_valid(value))
    {
        return Err(invalid_parameter("type"));
    }
    if name.is_some() && service_type.is_none() {
        return Err(invalid_parameter("type"));
    }
    let Some(question) = service_question(name.as_deref(), service_type.as_deref(), domain) else {
        return Err(invalid_parameter("domain"));
    };
    Ok(ServiceRequest {
        question,
        family,
        ifindex,
        flags,
    })
}

fn resolve_service_entries(
    records: crate::wire::ServiceRecords,
    resolver: &Resolver,
    request: &ServiceRequest,
) -> ServiceEntries {
    let mut root_target = false;
    let mut values = Vec::new();
    let mut last_address_error = None;
    for record in records.srv {
        if record.target.text() == "." {
            root_target = true;
            continue;
        }
        let mut fields = BTreeMap::from([
            (
                "priority".to_owned(),
                Value::Number(i128::from(record.priority)),
            ),
            (
                "weight".to_owned(),
                Value::Number(i128::from(record.weight)),
            ),
            ("port".to_owned(), Value::Number(i128::from(record.port))),
            (
                "hostname".to_owned(),
                Value::String(record.target.text().to_owned()),
            ),
        ]);
        if request.flags & SD_RESOLVED_NO_ADDRESS == 0 {
            let lookup = match resolver.lookup_name_on_link(
                record.target.text(),
                request.family,
                (request.ifindex > 0).then_some(request.ifindex),
            ) {
                Ok(lookup) => lookup,
                Err(error) => {
                    last_address_error = Some(error);
                    continue;
                }
            };
            let addresses = lookup
                .addresses
                .into_iter()
                .map(|address| resolved_address(address, request.ifindex))
                .collect();
            fields.insert(
                "canonicalName".to_owned(),
                Value::String(lookup.canonical_name),
            );
            fields.insert("addresses".to_owned(), Value::Array(addresses));
        }
        values.push(Value::Object(fields));
    }
    ServiceEntries {
        values,
        root_target,
        last_address_error,
    }
}

fn service_parameters(
    question: &ServiceQuestion,
    services: Vec<Value>,
    srv_response: &[u8],
    request_flags: u64,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("services".to_owned(), Value::Array(services)),
        (
            "canonical".to_owned(),
            Value::object([
                (
                    "name",
                    question
                        .name
                        .as_ref()
                        .map_or(Value::Null, |name| Value::String(name.clone())),
                ),
                ("type", Value::String(question.service_type.clone())),
                ("domain", Value::String(question.domain.clone())),
            ]),
        ),
        (
            "flags".to_owned(),
            Value::Number(i128::from(
                response_flags(srv_response)
                    | (request_flags & (SD_RESOLVED_NO_ADDRESS | SD_RESOLVED_NO_TXT)),
            )),
        ),
    ])
}

fn add_service_txt(
    output: &mut BTreeMap<String, Value>,
    request: &ServiceRequest,
    resolver: &Resolver,
) -> Result<(), Value> {
    if request.flags & SD_RESOLVED_NO_TXT != 0 {
        return Ok(());
    }
    let response = match resolver.resolve_record_on_link(
        &request.question.owner,
        CLASS_IN,
        TYPE_TXT,
        (request.ifindex > 0).then_some(request.ifindex),
    ) {
        Ok(response) => response,
        Err(ResolveError::NoSuchResourceRecord) => return Ok(()),
        Err(error) => return Err(resolver_error(&error)),
    };
    let Ok(records) = extract_service_records(&response) else {
        return Err(error("io.systemd.Resolve.InvalidReply"));
    };
    if !records.txt.is_empty() {
        output.insert(
            "txt".to_owned(),
            Value::Array(
                records
                    .txt
                    .iter()
                    .map(|item| Value::String(octescape(item)))
                    .collect(),
            ),
        );
    }
    Ok(())
}

fn resolved_address(address: IpAddr, ifindex: i32) -> Value {
    let (family, bytes): (i32, Vec<u8>) = match address {
        IpAddr::V4(address) => (2, address.octets().to_vec()),
        IpAddr::V6(address) => (10, address.octets().to_vec()),
    };
    let mut fields = BTreeMap::from([
        ("family".to_owned(), Value::Number(i128::from(family))),
        (
            "address".to_owned(),
            Value::Array(
                bytes
                    .into_iter()
                    .map(|byte| Value::Number(i128::from(byte)))
                    .collect(),
            ),
        ),
    ]);
    if ifindex > 0 {
        fields.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
    }
    Value::Object(fields)
}

fn service_question(
    name: Option<&str>,
    service_type: Option<&str>,
    domain: &str,
) -> Option<ServiceQuestion> {
    let name = name.filter(|value| !value.is_empty());
    let service_type = service_type.filter(|value| !value.is_empty());
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() || name.is_some_and(|value| !service_instance_is_valid(value)) {
        return None;
    }

    let (canonical_name, canonical_type, canonical_domain, owner) =
        if let Some(service_type) = service_type {
            if !service_type_is_valid(service_type) {
                return None;
            }
            let owner = if let Some(name) = name {
                format!("{name}.{service_type}.{domain}")
            } else {
                format!("{service_type}.{domain}")
            };
            (
                name.map(str::to_owned),
                service_type.to_ascii_lowercase(),
                domain.to_ascii_lowercase(),
                owner,
            )
        } else {
            if name.is_some() {
                return None;
            }
            let owner = domain.to_owned();
            let (name, service_type, domain) = split_service_owner(domain)?;
            (name, service_type, domain, owner)
        };
    make_query(&owner, TYPE_SRV, 0).ok()?;
    Some(ServiceQuestion {
        owner,
        name: canonical_name,
        service_type: canonical_type,
        domain: canonical_domain,
    })
}

fn split_service_owner(owner: &str) -> Option<(Option<String>, String, String)> {
    let labels: Vec<_> = owner.split('.').collect();
    for index in 0..labels.len().saturating_sub(2) {
        let candidate = format!("{}.{}", labels[index], labels[index + 1]);
        if !service_type_is_valid(&candidate) {
            continue;
        }
        let domain = labels.get(index + 2..)?.join(".");
        if domain.is_empty() || index > 1 {
            return None;
        }
        let name = (index == 1).then(|| labels[0].to_owned());
        if name
            .as_deref()
            .is_some_and(|value| !service_instance_is_valid(value))
        {
            return None;
        }
        return Some((
            name,
            candidate.to_ascii_lowercase(),
            domain.to_ascii_lowercase(),
        ));
    }
    None
}

fn service_instance_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.is_ascii()
        && !value.bytes().any(|byte| byte == b'.' || byte == 0)
}

fn service_type_is_valid(value: &str) -> bool {
    let mut labels = value.trim_end_matches('.').split('.');
    let Some(service) = labels.next() else {
        return false;
    };
    let Some(protocol) = labels.next() else {
        return false;
    };
    labels.next().is_none()
        && service.starts_with('_')
        && service.len() > 1
        && service.len() <= 63
        && protocol.starts_with('_')
        && protocol.len() > 1
        && protocol.len() <= 63
        && service.is_ascii()
        && protocol.is_ascii()
        && service
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && protocol
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn octescape(input: &[u8]) -> String {
    let mut output = String::new();
    for &byte in input {
        if (0x20..=0x7e).contains(&byte) && byte != b'\\' {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "\\{byte:03o}");
        }
    }
    output
}

fn response_flags(response: &[u8]) -> u64 {
    Header::parse(response).map_or(0, |header| {
        let mut flags = 1u64 << 10;
        if header.flags & 0x0020 != 0 {
            flags |= 1u64 << 9;
        }
        flags
    })
}

fn resolve_record(parameters: &Value, resolver: &Resolver) -> Value {
    let Some(name) = parameters.get("name").and_then(Value::as_str) else {
        return invalid_parameter("name");
    };
    if name.is_empty() {
        return invalid_parameter("name");
    }
    let class = match optional_u16(parameters, "class", CLASS_IN) {
        Ok(value) if value == CLASS_IN || value == CLASS_ANY => value,
        Ok(_) => return invalid_parameter("class"),
        Err(error) => return error,
    };
    let rr_type = match required_u16(parameters, "type") {
        Ok(0 | 41 | 249 | 250) => {
            return error("io.systemd.Resolve.ResourceRecordTypeInvalidForQuery")
        }
        Ok(251 | 252) => return error("io.systemd.Resolve.ZoneTransfersNotPermitted"),
        Ok(value) => value,
        Err(error) => return error,
    };
    let ifindex = match optional_i32(parameters, "ifindex", 0) {
        Ok(value) if value >= 0 => value,
        Ok(_) => return invalid_parameter("ifindex"),
        Err(error) => return error,
    };

    let response = match resolver.resolve_record_on_link(
        name,
        class,
        rr_type,
        (ifindex > 0).then_some(ifindex),
    ) {
        Ok(response) => response,
        Err(error) => return resolver_error(&error),
    };
    let records = match extract_answer_records(&response) {
        Ok(records) if !records.is_empty() => records,
        Ok(_) => return error("io.systemd.Resolve.NoSuchResourceRecord"),
        Err(_) => return error("io.systemd.Resolve.InvalidReply"),
    };
    let flags = response_flags(&response);
    let rrs = records
        .into_iter()
        .map(|record| {
            let mut fields = BTreeMap::new();
            if ifindex > 0 {
                fields.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
            }
            fields.insert("raw".to_owned(), Value::String(base64(&record.raw)));
            Value::Object(fields)
        })
        .collect();

    success(Value::object([
        ("rrs", Value::Array(rrs)),
        ("flags", Value::Number(i128::from(flags))),
    ]))
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        } else {
            output.push('=');
        }
    }
    output
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

fn required_u16(parameters: &Value, key: &str) -> Result<u16, Value> {
    parameters
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| invalid_parameter(key))
}

fn optional_u16(parameters: &Value, key: &str, default: u16) -> Result<u16, Value> {
    match parameters.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| invalid_parameter(key)),
    }
}

fn optional_u64(parameters: &Value, key: &str, default: u64) -> Result<u64, Value> {
    match parameters.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value.as_u64().ok_or_else(|| invalid_parameter(key)),
    }
}

fn optional_string(parameters: &Value, key: &str) -> Result<Option<String>, Value> {
    match parameters.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| (!value.is_empty()).then_some(value.to_owned()))
            .ok_or_else(|| invalid_parameter(key)),
    }
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

fn resolver_error(error_value: &ResolveError) -> Value {
    if let ResolveError::DnssecValidationFailed {
        result,
        extended_dns_error_code,
        extended_dns_error_message,
    } = error_value
    {
        return Value::object([
            (
                "error",
                Value::String("io.systemd.Resolve.DNSSECValidationFailed".to_owned()),
            ),
            (
                "parameters",
                Value::object([
                    ("result", Value::String(result.clone())),
                    (
                        "extendedDNSErrorCode",
                        extended_dns_error_code
                            .map_or(Value::Null, |code| Value::Number(i128::from(code))),
                    ),
                    (
                        "extendedDNSErrorMessage",
                        extended_dns_error_message
                            .as_ref()
                            .map_or(Value::Null, |message| Value::String(message.clone())),
                    ),
                ]),
            ),
        ]);
    }
    if let ResolveError::DnsError { rcode, query } = error_value {
        return Value::object([
            (
                "error",
                Value::String("io.systemd.Resolve.DNSError".to_owned()),
            ),
            (
                "parameters",
                Value::object([
                    ("rcode", Value::Number(i128::from(*rcode))),
                    ("queryString", Value::String(query.clone())),
                ]),
            ),
        ]);
    }
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
    fn activation_descriptor_selection_is_strict() {
        assert_eq!(activated_varlink_fd(0, None).expect("no activation"), None);
        assert_eq!(
            activated_varlink_fd(1, None).expect("unnamed activation"),
            Some(3)
        );
        assert_eq!(
            activated_varlink_fd(1, Some("varlink")).expect("named activation"),
            Some(3)
        );
        assert!(activated_varlink_fd(1, Some("other")).is_err());
        assert!(activated_varlink_fd(2, Some("varlink:other")).is_err());
    }

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
    fn base64_uses_standard_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }

    #[test]
    fn resolve_record_returns_raw_record_data() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"io.systemd.Resolve.ResolveRecord","parameters":{"name":"localhost","class":1,"type":1}}"#,
            &resolver,
        );
        let rrs = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("rrs"))
            .and_then(Value::as_array)
            .expect("resource records");
        assert!(!rrs.is_empty());
        assert!(rrs[0]
            .get("raw")
            .and_then(Value::as_str)
            .is_some_and(|raw| !raw.is_empty()));
    }

    #[test]
    fn refused_record_returns_structured_dns_error() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA\n")
            .expect("refuse configuration");
        let resolver = Resolver::new(config);
        let reply = dispatch(
            r#"{"method":"io.systemd.Resolve.ResolveRecord","parameters":{"name":"localhost","class":1,"type":28}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("io.systemd.Resolve.DNSError")
        );
        let parameters = reply.get("parameters").expect("error parameters");
        assert_eq!(parameters.get("rcode").and_then(Value::as_u64), Some(5));
        assert_eq!(
            parameters.get("queryString").and_then(Value::as_str),
            Some("localhost")
        );
    }

    #[test]
    fn refused_service_auxiliary_types_set_implicit_flags() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=A AAAA TXT\n")
            .expect("refuse configuration");
        let resolver = Resolver::new(config);
        let mut request = service_request(&Value::object([
            ("name", Value::Null),
            ("type", Value::String("_demo._tcp".to_owned())),
            ("domain", Value::String("example.test".to_owned())),
        ]))
        .expect("service request");
        apply_refused_service_flags(&mut request, &resolver);
        assert_ne!(request.flags & SD_RESOLVED_NO_ADDRESS, 0);
        assert_ne!(request.flags & SD_RESOLVED_NO_TXT, 0);
    }

    #[test]
    fn refusing_only_one_address_family_does_not_disable_addresses() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA\n")
            .expect("refuse configuration");
        let resolver = Resolver::new(config);
        let mut request = service_request(&Value::object([
            ("name", Value::Null),
            ("type", Value::String("_demo._tcp".to_owned())),
            ("domain", Value::String("example.test".to_owned())),
        ]))
        .expect("service request");
        apply_refused_service_flags(&mut request, &resolver);
        assert_eq!(request.flags & SD_RESOLVED_NO_ADDRESS, 0);
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

    fn spawn_service_server() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        use crate::wire::{encode_name, first_question, question_end, TYPE_A};
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let address = socket.local_addr().expect("test DNS address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            for _ in 0..3 {
                let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                    return;
                };
                let query = &buffer[..length];
                let question = first_question(query).expect("test question");
                let end = question_end(query).expect("test question end");
                let mut response = query[..end].to_vec();
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                response[6..8].copy_from_slice(&1u16.to_be_bytes());
                response[8..12].fill(0);

                let rdata = match question.rr_type {
                    TYPE_SRV => {
                        let mut rdata = Vec::new();
                        rdata.extend_from_slice(&10u16.to_be_bytes());
                        rdata.extend_from_slice(&20u16.to_be_bytes());
                        rdata.extend_from_slice(&631u16.to_be_bytes());
                        rdata.extend_from_slice(
                            &encode_name("host.example.test").expect("service target"),
                        );
                        rdata
                    }
                    TYPE_TXT => {
                        let item = b"path=/";
                        let mut rdata = vec![u8::try_from(item.len()).expect("TXT length")];
                        rdata.extend_from_slice(item);
                        rdata
                    }
                    TYPE_A => vec![192, 0, 2, 10],
                    other => panic!("unexpected test query type {other}"),
                };
                response.extend_from_slice(&[0xc0, 0x0c]);
                response.extend_from_slice(&question.rr_type.to_be_bytes());
                response.extend_from_slice(&CLASS_IN.to_be_bytes());
                response.extend_from_slice(&60u32.to_be_bytes());
                response.extend_from_slice(
                    &u16::try_from(rdata.len())
                        .expect("test RDATA length")
                        .to_be_bytes(),
                );
                response.extend_from_slice(&rdata);
                socket
                    .send_to(&response, peer)
                    .expect("send test DNS response");
            }
        });
        (address, worker)
    }

    #[test]
    fn resolve_service_returns_srv_txt_and_addresses() {
        let (server, worker) = spawn_service_server();
        let config = Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        let reply = dispatch(
            r#"{"method":"io.systemd.Resolve.ResolveService","parameters":{"name":null,"type":"_demo._tcp","domain":"example.test","family":2}}"#,
            &resolver,
        );
        worker.join().expect("test DNS worker");

        assert!(reply.get("error").is_none(), "{}", reply.to_json());
        let parameters = reply.get("parameters").expect("reply parameters");
        let services = parameters
            .get("services")
            .and_then(Value::as_array)
            .expect("services");
        assert_eq!(services.len(), 1);
        assert_eq!(
            services[0].get("hostname").and_then(Value::as_str),
            Some("host.example.test")
        );
        assert_eq!(
            services[0]
                .get("addresses")
                .and_then(Value::as_array)
                .and_then(|addresses| addresses.first())
                .and_then(|address| address.get("family"))
                .and_then(Value::as_i64),
            Some(2)
        );
        assert_eq!(
            parameters
                .get("txt")
                .and_then(Value::as_array)
                .and_then(|txt| txt.first())
                .and_then(Value::as_str),
            Some("path=/")
        );
    }

    #[test]
    fn service_question_supports_dns_sd_and_plain_srv_names() {
        let dns_sd = service_question(Some("Printer"), Some("_ipp._tcp"), "example.test")
            .expect("DNS-SD question");
        assert_eq!(dns_sd.owner, "Printer._ipp._tcp.example.test");
        assert_eq!(dns_sd.name.as_deref(), Some("Printer"));
        assert_eq!(dns_sd.service_type, "_ipp._tcp");
        assert_eq!(dns_sd.domain, "example.test");

        let plain =
            service_question(None, None, "_ldap._tcp.example.test").expect("plain SRV question");
        assert_eq!(plain.owner, "_ldap._tcp.example.test");
        assert_eq!(plain.name, None);
        assert_eq!(plain.service_type, "_ldap._tcp");
        assert_eq!(plain.domain, "example.test");
    }

    #[test]
    fn service_question_rejects_name_without_type() {
        assert!(service_question(Some("Printer"), None, "example.test").is_none());
    }

    #[test]
    fn pinned_error_identifiers_and_dnssec_parameters_are_exact() {
        let errors = [
            ResolveError::QueryAborted,
            ResolveError::QueryRefused,
            ResolveError::NoTrustAnchor,
            ResolveError::StubLoop,
            ResolveError::ResourceRecordTypeObsolete,
            ResolveError::InconsistentServiceRecords,
        ];
        let identifiers: Vec<_> = errors.iter().map(ResolveError::varlink_id).collect();
        assert_eq!(
            identifiers,
            vec![
                "io.systemd.Resolve.QueryAborted",
                "io.systemd.Resolve.QueryRefused",
                "io.systemd.Resolve.NoTrustAnchor",
                "io.systemd.Resolve.StubLoop",
                "io.systemd.Resolve.ResourceRecordTypeObsolete",
                "io.systemd.Resolve.InconsistentServiceRecords",
            ]
        );

        let dnssec = ResolveError::DnssecValidationFailed {
            result: "bogus".to_owned(),
            extended_dns_error_code: Some(6),
            extended_dns_error_message: Some("signature expired".to_owned()),
        };
        let reply = resolver_error(&dnssec);
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("io.systemd.Resolve.DNSSECValidationFailed")
        );
        let parameters = reply.get("parameters").expect("DNSSEC error parameters");
        assert_eq!(
            parameters.get("result").and_then(Value::as_str),
            Some("bogus")
        );
        assert_eq!(
            parameters
                .get("extendedDNSErrorCode")
                .and_then(Value::as_u64),
            Some(6)
        );
        assert_eq!(
            parameters
                .get("extendedDNSErrorMessage")
                .and_then(Value::as_str),
            Some("signature expired")
        );
    }

    #[test]
    fn interface_description_lists_pinned_error_identifiers() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"org.varlink.service.GetInterfaceDescription","parameters":{"interface":"io.systemd.Resolve"}}"#,
            &resolver,
        );
        let description = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("description"))
            .and_then(Value::as_str)
            .expect("interface description");
        for symbol in [
            "DNSSECValidationFailed",
            "InconsistentServiceRecords",
            "NoTrustAnchor",
            "QueryAborted",
            "QueryRefused",
            "ResourceRecordTypeObsolete",
            "StubLoop",
        ] {
            assert!(description.contains(symbol), "missing {symbol}");
        }
    }

    #[test]
    fn txt_octescape_preserves_printable_bytes() {
        assert_eq!(octescape(b"path=/"), "path=/");
        assert_eq!(octescape(&[0, b'\\', 0xff]), "\\000\\134\\377");
    }
}
