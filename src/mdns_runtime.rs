// SPDX-License-Identifier: LGPL-2.1-or-later
use super::parity::{
    canonical_wire_name, validate_ingress, MdnsAddressFamily, MdnsCache, MdnsIngressMeta,
    MdnsInterface, MdnsMessageKind, MdnsRecordKey, MDNS_IPV4_MULTICAST,
    MDNS_IPV6_MULTICAST, MDNS_PORT,
};
use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const DNS_HEADER_LENGTH: usize = 12;
const DNS_FLAG_QR: u16 = 1 << 15;
const DNS_FLAG_AA: u16 = 1 << 10;
const DNS_FLAG_TC: u16 = 1 << 9;
const DNS_FLAG_RD: u16 = 1 << 8;
const DNS_FLAG_RA: u16 = 1 << 7;
const DNS_CLASS_MASK: u16 = 0x7fff;
const DNS_CLASS_CACHE_FLUSH: u16 = 0x8000;
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_DNAME: u16 = 39;
const TYPE_NSEC: u16 = 47;
const TYPE_ANY: u16 = 255;
const RESPONSE_SETTLE_TIME: Duration = Duration::from_millis(120);
const RECEIVE_SLEEP: Duration = Duration::from_millis(5);
const MAX_MDNS_PACKET: usize = 65_535;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeMdnsInterface {
    family: i32,
    ifindex: u32,
    address: [u8; 16],
    scope_id: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeMdnsMeta {
    family: i32,
    port: u16,
    reserved: u16,
    source: [u8; 16],
    destination: [u8; 16],
    ifindex: u32,
    hop_limit: u32,
}

extern "C" {
    fn resolved_rs_mdns_interfaces(
        output: *mut NativeMdnsInterface,
        capacity: usize,
    ) -> isize;
    fn resolved_rs_mdns_open(family: i32, ifindex: u32, port: u16) -> i32;
    fn resolved_rs_mdns_recv(
        fd: i32,
        buffer: *mut u8,
        capacity: usize,
        metadata: *mut NativeMdnsMeta,
    ) -> isize;
}

#[derive(Debug)]
pub enum MdnsRuntimeError {
    Io(io::Error),
    InvalidQuery(&'static str),
    InvalidResponse(&'static str),
}

impl fmt::Display for MdnsRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::InvalidQuery(message) | Self::InvalidResponse(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl Error for MdnsRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidQuery(_) | Self::InvalidResponse(_) => None,
        }
    }
}

impl From<io::Error> for MdnsRuntimeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug)]
struct RuntimeInterface {
    interface: MdnsInterface,
    address: IpAddr,
}

#[derive(Debug)]
struct RuntimeSocket {
    interface: MdnsInterface,
    socket: UdpSocket,
}

#[derive(Clone, Debug)]
struct MdnsQuestion {
    id: u16,
    flags: u16,
    owner: Vec<u8>,
    text: String,
    rr_type: u16,
    class: u16,
    raw: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RuntimeRecord {
    owner: Vec<u8>,
    rr_type: u16,
    class: u16,
    ttl: u32,
    cache_flush: bool,
    rdata: Vec<u8>,
    interface: MdnsInterface,
}

static CACHE: OnceLock<Mutex<MdnsCache>> = OnceLock::new();

fn cache() -> MutexGuard<'static, MdnsCache> {
    CACHE
        .get_or_init(|| Mutex::new(MdnsCache::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn flush_cache() {
    cache().flush();
}

pub fn should_handle_query(query: &[u8]) -> bool {
    parse_question(query)
        .map(|question| should_handle_name(&question.text))
        .unwrap_or(false)
}

pub fn should_handle_name(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name == "local"
        || name.ends_with(".local")
        || name.ends_with(".254.169.in-addr.arpa")
        || name.ends_with(".8.e.f.ip6.arpa")
}

pub fn query_raw(
    query: &[u8],
    requested_ifindex: Option<i32>,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, MdnsRuntimeError> {
    if !mdns_enabled() {
        return Ok(None);
    }
    let question = parse_question(query)?;
    if !should_handle_name(&question.text) {
        return Ok(None);
    }
    if question.class & DNS_CLASS_MASK != 1 {
        return Ok(None);
    }

    let requested_ifindex = match requested_ifindex {
        Some(index) if index <= 0 => {
            return Err(MdnsRuntimeError::InvalidQuery(
                "mDNS interface index must be positive",
            ));
        }
        Some(index) => Some(u32::try_from(index).map_err(|_| {
            MdnsRuntimeError::InvalidQuery("mDNS interface index is out of range")
        })?),
        None => None,
    };
    let interfaces = interfaces()?
        .into_iter()
        .filter(|entry| requested_ifindex.map_or(true, |index| entry.interface.ifindex == index))
        .collect::<Vec<_>>();
    if interfaces.is_empty() {
        return Ok(None);
    }

    let cached = cached_records(&question, &interfaces, Instant::now())?;
    if !cached.is_empty() {
        return Ok(Some(build_stub_response(&question, &cached, &[])?));
    }

    let mut sockets = open_sockets(&interfaces)?;
    if sockets.is_empty() {
        return Ok(None);
    }
    let multicast_query = build_multicast_query(&question);
    for endpoint in &sockets {
        let destination = multicast_destination(endpoint.interface);
        match endpoint.socket.send_to(&multicast_query, destination) {
            Ok(length) if length == multicast_query.len() => {}
            Ok(_) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short mDNS send").into())
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }

    let now = Instant::now();
    let timeout = timeout
        .min(Duration::from_secs(5))
        .max(Duration::from_millis(250));
    let deadline = now + timeout;
    let mut settle_deadline = None;
    let mut answers = BTreeSet::new();
    let mut additionals = BTreeSet::new();
    let mut buffer = vec![0u8; MAX_MDNS_PACKET];

    while Instant::now() < deadline {
        let mut received = false;
        for endpoint in &mut sockets {
            loop {
                let Some(datagram) = recv_datagram(endpoint, &mut buffer)? else {
                    break;
                };
                received = true;
                let metadata = datagram.metadata;
                let validated = match validate_ingress(datagram.packet, metadata) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if validated.kind != MdnsMessageKind::Response
                    || validated.interface != endpoint.interface
                {
                    continue;
                }
                let records = parse_response_records(datagram.packet, endpoint.interface)?;
                let received_at = Instant::now();
                for record in records {
                    if record.class & DNS_CLASS_MASK != 1 {
                        continue;
                    }
                    let key = MdnsRecordKey::new(
                        record.interface,
                        &record.owner,
                        record.rr_type,
                        record.class,
                    )
                    .map_err(|_| MdnsRuntimeError::InvalidResponse("invalid mDNS owner"))?;
                    cache().insert(
                        key,
                        record.rdata.clone(),
                        record.ttl,
                        record.cache_flush,
                        received_at,
                    );
                    if record_matches(&question, &record) {
                        answers.insert(record);
                    } else {
                        additionals.insert(record);
                    }
                }
                if !answers.is_empty() {
                    settle_deadline = Some(Instant::now() + RESPONSE_SETTLE_TIME);
                }
            }
        }
        if settle_deadline.is_some_and(|settle| Instant::now() >= settle) {
            break;
        }
        if !received {
            thread::sleep(RECEIVE_SLEEP);
        }
    }

    if answers.is_empty() {
        return Ok(None);
    }
    Ok(Some(build_stub_response(
        &question,
        &answers.into_iter().collect::<Vec<_>>(),
        &additionals.into_iter().collect::<Vec<_>>(),
    )?))
}

fn mdns_enabled() -> bool {
    std::env::var("RESOLVED_RS_MDNS")
        .map(|value| {
            !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "no" | "false" | "off"
            )
        })
        .unwrap_or(true)
}

fn interfaces() -> Result<Vec<RuntimeInterface>, MdnsRuntimeError> {
    // SAFETY: a null pointer with zero capacity is the documented count query.
    let count = unsafe { resolved_rs_mdns_interfaces(std::ptr::null_mut(), 0) };
    if count < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let capacity = usize::try_from(count)
        .map_err(|_| MdnsRuntimeError::InvalidResponse("too many network interfaces"))?;
    let mut native = vec![NativeMdnsInterface::default(); capacity];
    // SAFETY: native owns capacity initialized entries and the C function writes at most capacity.
    let populated = unsafe { resolved_rs_mdns_interfaces(native.as_mut_ptr(), native.len()) };
    if populated < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let populated = usize::try_from(populated)
        .map_err(|_| MdnsRuntimeError::InvalidResponse("invalid interface count"))?
        .min(native.len());
    native.truncate(populated);

    let mut output = Vec::new();
    for entry in native {
        let (family, address) = match entry.family {
            AF_INET => (
                MdnsAddressFamily::Ipv4,
                IpAddr::V4(Ipv4Addr::new(
                    entry.address[0],
                    entry.address[1],
                    entry.address[2],
                    entry.address[3],
                )),
            ),
            AF_INET6 => (MdnsAddressFamily::Ipv6, IpAddr::V6(Ipv6Addr::from(entry.address))),
            _ => continue,
        };
        output.push(RuntimeInterface {
            interface: MdnsInterface::new(entry.ifindex, family),
            address,
        });
    }
    Ok(output)
}

fn open_sockets(interfaces: &[RuntimeInterface]) -> Result<Vec<RuntimeSocket>, MdnsRuntimeError> {
    let mut keys = HashSet::new();
    let mut output = Vec::new();
    for entry in interfaces {
        if !keys.insert(entry.interface) {
            continue;
        }
        let family = match entry.interface.family {
            MdnsAddressFamily::Ipv4 => AF_INET,
            MdnsAddressFamily::Ipv6 => AF_INET6,
        };
        // SAFETY: the native function returns a fresh owned descriptor on success.
        let fd = unsafe { resolved_rs_mdns_open(family, entry.interface.ifindex, MDNS_PORT) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::PermissionDenied
            ) {
                continue;
            }
            return Err(error.into());
        }
        // SAFETY: ownership of the fresh descriptor is transferred exactly once.
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        output.push(RuntimeSocket {
            interface: entry.interface,
            socket,
        });
    }
    Ok(output)
}

fn multicast_destination(interface: MdnsInterface) -> SocketAddr {
    match interface.family {
        MdnsAddressFamily::Ipv4 => SocketAddr::new(IpAddr::V4(MDNS_IPV4_MULTICAST), MDNS_PORT),
        MdnsAddressFamily::Ipv6 => SocketAddr::V6(std::net::SocketAddrV6::new(
            MDNS_IPV6_MULTICAST,
            MDNS_PORT,
            0,
            interface.ifindex,
        )),
    }
}

struct ReceivedDatagram<'a> {
    packet: &'a [u8],
    metadata: MdnsIngressMeta,
}

fn recv_datagram<'a>(
    endpoint: &RuntimeSocket,
    buffer: &'a mut [u8],
) -> Result<Option<ReceivedDatagram<'a>>, MdnsRuntimeError> {
    let mut native = NativeMdnsMeta::default();
    // SAFETY: buffer and native are valid writable objects for the supplied lengths.
    let length = unsafe {
        resolved_rs_mdns_recv(
            endpoint.socket.as_raw_fd(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut native,
        )
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Ok(None);
        }
        return Err(error.into());
    }
    let length = usize::try_from(length)
        .map_err(|_| MdnsRuntimeError::InvalidResponse("negative mDNS packet length"))?;
    if length > buffer.len() {
        return Err(MdnsRuntimeError::InvalidResponse(
            "native mDNS receive exceeded its buffer",
        ));
    }
    let (source_ip, destination_ip) = match native.family {
        AF_INET => (
            IpAddr::V4(Ipv4Addr::new(
                native.source[0],
                native.source[1],
                native.source[2],
                native.source[3],
            )),
            IpAddr::V4(Ipv4Addr::new(
                native.destination[0],
                native.destination[1],
                native.destination[2],
                native.destination[3],
            )),
        ),
        AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(native.source)),
            IpAddr::V6(Ipv6Addr::from(native.destination)),
        ),
        _ => {
            return Err(MdnsRuntimeError::InvalidResponse(
                "native mDNS receive returned an unsupported family",
            ))
        }
    };
    let destination = match destination_ip {
        IpAddr::V4(address) => SocketAddr::new(IpAddr::V4(address), MDNS_PORT),
        IpAddr::V6(address) => SocketAddr::V6(std::net::SocketAddrV6::new(
            address,
            MDNS_PORT,
            0,
            native.ifindex,
        )),
    };
    Ok(Some(ReceivedDatagram {
        packet: &buffer[..length],
        metadata: MdnsIngressMeta {
            source: SocketAddr::new(source_ip, native.port),
            destination,
            ifindex: Some(native.ifindex),
            hop_limit: Some(native.hop_limit),
            received_multicast: matches!(
                destination_ip,
                IpAddr::V4(address) if address == MDNS_IPV4_MULTICAST
            ) || matches!(
                destination_ip,
                IpAddr::V6(address) if address == MDNS_IPV6_MULTICAST
            ),
        },
    }))
}

fn parse_question(packet: &[u8]) -> Result<MdnsQuestion, MdnsRuntimeError> {
    if packet.len() < DNS_HEADER_LENGTH {
        return Err(MdnsRuntimeError::InvalidQuery("short DNS query"));
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    if flags & DNS_FLAG_QR != 0 || flags & 0x7800 != 0 {
        return Err(MdnsRuntimeError::InvalidQuery("invalid mDNS query flags"));
    }
    if read_u16(packet, 4)? != 1 {
        return Err(MdnsRuntimeError::InvalidQuery(
            "mDNS translation requires exactly one question",
        ));
    }
    let (owner, text, end) = decode_name(packet, DNS_HEADER_LENGTH)?;
    if end + 4 > packet.len() {
        return Err(MdnsRuntimeError::InvalidQuery("truncated DNS question"));
    }
    let rr_type = read_u16(packet, end)?;
    let class = read_u16(packet, end + 2)?;
    Ok(MdnsQuestion {
        id,
        flags,
        owner,
        text,
        rr_type,
        class,
        raw: packet[DNS_HEADER_LENGTH..end + 4].to_vec(),
    })
}

fn build_multicast_query(question: &MdnsQuestion) -> Vec<u8> {
    let mut output = Vec::with_capacity(DNS_HEADER_LENGTH + question.raw.len());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&question.owner);
    output.extend_from_slice(&question.rr_type.to_be_bytes());
    output.extend_from_slice(&(question.class & DNS_CLASS_MASK).to_be_bytes());
    output
}

fn parse_response_records(
    packet: &[u8],
    interface: MdnsInterface,
) -> Result<Vec<RuntimeRecord>, MdnsRuntimeError> {
    if packet.len() < DNS_HEADER_LENGTH {
        return Err(MdnsRuntimeError::InvalidResponse("short mDNS response"));
    }
    let questions = read_u16(packet, 4)?;
    let answers = read_u16(packet, 6)?;
    let authorities = read_u16(packet, 8)?;
    let additionals = read_u16(packet, 10)?;
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        let (_, _, end) = decode_name(packet, offset)?;
        offset = end
            .checked_add(4)
            .filter(|value| *value <= packet.len())
            .ok_or(MdnsRuntimeError::InvalidResponse(
                "truncated mDNS question",
            ))?;
    }
    let count = u32::from(answers) + u32::from(authorities) + u32::from(additionals);
    let mut output = Vec::new();
    for _ in 0..count {
        let (owner, _, end) = decode_name(packet, offset)?;
        if end + 10 > packet.len() {
            return Err(MdnsRuntimeError::InvalidResponse(
                "truncated mDNS record header",
            ));
        }
        let rr_type = read_u16(packet, end)?;
        let raw_class = read_u16(packet, end + 2)?;
        let ttl = read_u32(packet, end + 4)?;
        let length = usize::from(read_u16(packet, end + 8)?);
        let rdata_start = end + 10;
        let rdata_end = rdata_start
            .checked_add(length)
            .filter(|value| *value <= packet.len())
            .ok_or(MdnsRuntimeError::InvalidResponse(
                "truncated mDNS record data",
            ))?;
        let rdata = expand_rdata(packet, rr_type, rdata_start, rdata_end)?;
        output.push(RuntimeRecord {
            owner,
            rr_type,
            class: raw_class & DNS_CLASS_MASK,
            ttl,
            cache_flush: raw_class & DNS_CLASS_CACHE_FLUSH != 0,
            rdata,
            interface,
        });
        offset = rdata_end;
    }
    if offset != packet.len() {
        return Err(MdnsRuntimeError::InvalidResponse(
            "trailing data after mDNS response",
        ));
    }
    Ok(output)
}

fn expand_rdata(
    packet: &[u8],
    rr_type: u16,
    start: usize,
    end: usize,
) -> Result<Vec<u8>, MdnsRuntimeError> {
    match rr_type {
        TYPE_NS | TYPE_CNAME | TYPE_PTR | TYPE_DNAME => {
            let (name, _, consumed) = decode_name(packet, start)?;
            if consumed != end {
                return Err(MdnsRuntimeError::InvalidResponse(
                    "trailing name record data",
                ));
            }
            Ok(name)
        }
        TYPE_MX => {
            if start + 2 > end {
                return Err(MdnsRuntimeError::InvalidResponse("short MX record"));
            }
            let (name, _, consumed) = decode_name(packet, start + 2)?;
            if consumed != end {
                return Err(MdnsRuntimeError::InvalidResponse("trailing MX data"));
            }
            let mut output = packet[start..start + 2].to_vec();
            output.extend_from_slice(&name);
            Ok(output)
        }
        TYPE_SRV => {
            if start + 6 > end {
                return Err(MdnsRuntimeError::InvalidResponse("short SRV record"));
            }
            let (name, _, consumed) = decode_name(packet, start + 6)?;
            if consumed != end {
                return Err(MdnsRuntimeError::InvalidResponse("trailing SRV data"));
            }
            let mut output = packet[start..start + 6].to_vec();
            output.extend_from_slice(&name);
            Ok(output)
        }
        TYPE_SOA => {
            let (mname, _, cursor) = decode_name(packet, start)?;
            let (rname, _, cursor) = decode_name(packet, cursor)?;
            if cursor + 20 != end {
                return Err(MdnsRuntimeError::InvalidResponse("invalid SOA data"));
            }
            let mut output = mname;
            output.extend_from_slice(&rname);
            output.extend_from_slice(&packet[cursor..end]);
            Ok(output)
        }
        TYPE_NSEC => {
            let (next, _, cursor) = decode_name(packet, start)?;
            if cursor > end {
                return Err(MdnsRuntimeError::InvalidResponse("invalid NSEC data"));
            }
            let mut output = next;
            output.extend_from_slice(&packet[cursor..end]);
            Ok(output)
        }
        _ => Ok(packet[start..end].to_vec()),
    }
}

fn decode_name(
    packet: &[u8],
    start: usize,
) -> Result<(Vec<u8>, String, usize), MdnsRuntimeError> {
    let mut output = Vec::new();
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut next = None;
    let mut visited = HashSet::new();
    for _ in 0..128 {
        let Some(&length) = packet.get(cursor) else {
            return Err(MdnsRuntimeError::InvalidResponse("truncated DNS name"));
        };
        if length & 0xc0 == 0xc0 {
            let second = *packet
                .get(cursor + 1)
                .ok_or(MdnsRuntimeError::InvalidResponse(
                    "truncated DNS compression pointer",
                ))?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if target >= packet.len() || !visited.insert(target) {
                return Err(MdnsRuntimeError::InvalidResponse(
                    "invalid DNS compression pointer",
                ));
            }
            if next.is_none() {
                next = Some(cursor + 2);
            }
            cursor = target;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(MdnsRuntimeError::InvalidResponse("invalid DNS label"));
        }
        cursor += 1;
        output.push(length);
        if length == 0 {
            let output = canonical_wire_name(&output)
                .map_err(|_| MdnsRuntimeError::InvalidResponse("invalid DNS name"))?;
            let text = if labels.is_empty() {
                ".".to_owned()
            } else {
                format!("{}.", labels.join("."))
            };
            return Ok((output, text, next.unwrap_or(cursor)));
        }
        let length = usize::from(length);
        let end = cursor
            .checked_add(length)
            .filter(|value| *value <= packet.len())
            .ok_or(MdnsRuntimeError::InvalidResponse("truncated DNS label"))?;
        let label = &packet[cursor..end];
        output.extend(label.iter().map(u8::to_ascii_lowercase));
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        cursor = end;
        if output.len() >= 255 {
            return Err(MdnsRuntimeError::InvalidResponse("DNS name is too long"));
        }
    }
    Err(MdnsRuntimeError::InvalidResponse(
        "too many DNS compression pointers",
    ))
}

fn record_matches(question: &MdnsQuestion, record: &RuntimeRecord) -> bool {
    record.owner == question.owner
        && (question.rr_type == TYPE_ANY || question.rr_type == record.rr_type)
        && (question.class & DNS_CLASS_MASK) == (record.class & DNS_CLASS_MASK)
}

fn cached_records(
    question: &MdnsQuestion,
    interfaces: &[RuntimeInterface],
    now: Instant,
) -> Result<Vec<RuntimeRecord>, MdnsRuntimeError> {
    if question.rr_type == TYPE_ANY {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in interfaces {
        let key = MdnsRecordKey::new(
            entry.interface,
            &question.owner,
            question.rr_type,
            question.class,
        )
        .map_err(|_| MdnsRuntimeError::InvalidQuery("invalid mDNS question owner"))?;
        for record in cache().lookup(&key, now) {
            let ttl = record.remaining_ttl(now).as_secs().min(u64::from(u32::MAX)) as u32;
            let candidate = RuntimeRecord {
                owner: question.owner.clone(),
                rr_type: question.rr_type,
                class: question.class & DNS_CLASS_MASK,
                ttl: ttl.max(1),
                cache_flush: record.cache_flush,
                rdata: record.rdata,
                interface: entry.interface,
            };
            if seen.insert(candidate.clone()) {
                output.push(candidate);
            }
        }
    }
    Ok(output)
}

fn build_stub_response(
    question: &MdnsQuestion,
    answers: &[RuntimeRecord],
    additionals: &[RuntimeRecord],
) -> Result<Vec<u8>, MdnsRuntimeError> {
    let answers = answers
        .iter()
        .filter(|record| record_matches(question, record))
        .collect::<BTreeSet<_>>();
    if answers.len() > usize::from(u16::MAX) || additionals.len() > usize::from(u16::MAX) {
        return Err(MdnsRuntimeError::InvalidResponse(
            "too many records in translated mDNS response",
        ));
    }
    let mut flags = DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA;
    flags |= question.flags & DNS_FLAG_RD;
    let mut output = Vec::new();
    output.extend_from_slice(&question.id.to_be_bytes());
    output.extend_from_slice(&flags.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&(additionals.len() as u16).to_be_bytes());
    output.extend_from_slice(&question.raw);
    for record in answers {
        append_record(&mut output, record)?;
    }
    for record in additionals {
        append_record(&mut output, record)?;
    }
    if output.len() > usize::from(u16::MAX) {
        output[2..4].copy_from_slice(&(flags | DNS_FLAG_TC).to_be_bytes());
        output.truncate(1232);
    }
    Ok(output)
}

fn append_record(output: &mut Vec<u8>, record: &RuntimeRecord) -> Result<(), MdnsRuntimeError> {
    let length = u16::try_from(record.rdata.len())
        .map_err(|_| MdnsRuntimeError::InvalidResponse("mDNS RDATA exceeds 65535 octets"))?;
    output.extend_from_slice(&record.owner);
    output.extend_from_slice(&record.rr_type.to_be_bytes());
    output.extend_from_slice(&(record.class & DNS_CLASS_MASK).to_be_bytes());
    output.extend_from_slice(&record.ttl.to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&record.rdata);
    Ok(())
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, MdnsRuntimeError> {
    let bytes = packet
        .get(offset..offset.saturating_add(2))
        .ok_or(MdnsRuntimeError::InvalidResponse("truncated DNS u16"))?;
    if bytes.len() != 2 {
        return Err(MdnsRuntimeError::InvalidResponse("truncated DNS u16"));
    }
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, MdnsRuntimeError> {
    let bytes = packet
        .get(offset..offset.saturating_add(4))
        .ok_or(MdnsRuntimeError::InvalidResponse("truncated DNS u32"))?;
    if bytes.len() != 4 {
        return Err(MdnsRuntimeError::InvalidResponse("truncated DNS u32"));
    }
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_name(labels: &[&str]) -> Vec<u8> {
        let mut output = Vec::new();
        for label in labels {
            output.push(u8::try_from(label.len()).expect("label length"));
            output.extend_from_slice(label.as_bytes());
        }
        output.push(0);
        output
    }

    fn query(name: &[&str], rr_type: u16) -> Vec<u8> {
        let owner = wire_name(name);
        let mut output = Vec::new();
        output.extend_from_slice(&0x1234u16.to_be_bytes());
        output.extend_from_slice(&DNS_FLAG_RD.to_be_bytes());
        output.extend_from_slice(&1u16.to_be_bytes());
        output.extend_from_slice(&0u16.to_be_bytes());
        output.extend_from_slice(&0u16.to_be_bytes());
        output.extend_from_slice(&0u16.to_be_bytes());
        output.extend_from_slice(&owner);
        output.extend_from_slice(&rr_type.to_be_bytes());
        output.extend_from_slice(&1u16.to_be_bytes());
        output
    }

    #[test]
    fn routes_local_and_link_local_reverse_names_only() {
        assert!(should_handle_name("host.local"));
        assert!(should_handle_name("1.0.254.169.in-addr.arpa"));
        assert!(should_handle_name("1.0.8.e.f.ip6.arpa"));
        assert!(!should_handle_name("example.com"));
    }

    #[test]
    fn translates_query_to_identifier_zero() {
        let parsed = parse_question(&query(&["host", "local"], TYPE_A)).expect("question");
        let multicast = build_multicast_query(&parsed);
        assert_eq!(&multicast[0..2], &[0, 0]);
        assert_eq!(read_u16(&multicast, 4).expect("question count"), 1);
    }

    #[test]
    fn expands_compressed_owner_and_ptr_data() {
        let owner = wire_name(&["_http", "_tcp", "local"]);
        let target = wire_name(&["Web", "_http", "_tcp", "local"]);
        let mut packet = vec![0u8; DNS_HEADER_LENGTH];
        packet[2..4].copy_from_slice(&(DNS_FLAG_QR | DNS_FLAG_AA).to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        let owner_offset = packet.len();
        packet.extend_from_slice(&owner);
        packet.extend_from_slice(&TYPE_PTR.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
        packet.extend_from_slice(&target);
        let records = parse_response_records(
            &packet,
            MdnsInterface::new(2, MdnsAddressFamily::Ipv4),
        )
        .expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].owner, owner);
        assert_eq!(records[0].rdata, canonical_wire_name(&target).expect("target"));
        assert_eq!(owner_offset, DNS_HEADER_LENGTH);
    }

    #[test]
    fn stub_translation_restores_id_and_clears_cache_flush() {
        let query = parse_question(&query(&["host", "local"], TYPE_A)).expect("question");
        let record = RuntimeRecord {
            owner: query.owner.clone(),
            rr_type: TYPE_A,
            class: 1,
            ttl: 120,
            cache_flush: true,
            rdata: vec![192, 0, 2, 10],
            interface: MdnsInterface::new(2, MdnsAddressFamily::Ipv4),
        };
        let response = build_stub_response(&query, &[record], &[]).expect("response");
        assert_eq!(read_u16(&response, 0).expect("id"), 0x1234);
        assert_eq!(read_u16(&response, 6).expect("answer count"), 1);
        let (_, _, owner_end) = decode_name(&response, DNS_HEADER_LENGTH).expect("question name");
        let answer_offset = owner_end + 4;
        let (_, _, answer_owner_end) = decode_name(&response, answer_offset).expect("answer owner");
        assert_eq!(
            read_u16(&response, answer_owner_end + 2).expect("class"),
            1
        );
    }

    #[test]
    fn interface_native_layout_matches_c_contract() {
        assert_eq!(std::mem::size_of::<NativeMdnsInterface>(), 32);
        assert_eq!(std::mem::size_of::<NativeMdnsMeta>(), 48);
    }
}
