fn lookup_candidates(
    name: &str,
    domains: &[Domain],
    resolve_unicast_single_label: bool,
) -> Vec<String> {
    let relative = name.trim_end_matches('.');
    if relative.is_empty() || name.ends_with('.') || relative.contains('.') {
        return vec![name.to_owned()];
    }

    let mut candidates = Vec::new();
    for domain in domains {
        if domain.route_only || domain.name == "." {
            continue;
        }
        let candidate = format!("{relative}.{}", domain.name);
        if !candidates
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(&candidate))
        {
            candidates.push(candidate);
        }
    }
    if resolve_unicast_single_label
        && !candidates
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(relative))
    {
        candidates.push(relative.to_owned());
    }
    candidates
}

fn normalize_shared_response(response: &[u8]) -> Option<Vec<u8>> {
    let mut response = response.to_vec();
    wire::rewrite_id(&mut response, 0).ok()?;
    Some(response)
}

fn response_is_success(response: &[u8]) -> bool {
    matches!(Header::parse(response), Ok(header) if header.response_code() == 0)
}

fn route_cache_id(generation: u64, ifindex: Option<i32>) -> u64 {
    let ifindex = ifindex
        .and_then(|value| u32::try_from(value).ok())
        .map_or(0, u64::from);
    generation.rotate_left(32) ^ ifindex
}

fn duration_milliseconds(duration: Duration) -> i32 {
    i32::try_from(duration.as_millis()).unwrap_or(i32::MAX)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameLookup {
    pub addresses: Vec<IpAddr>,
    pub canonical_name: String,
    pub flags: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressLookup {
    pub names: Vec<String>,
    pub flags: u64,
}

#[derive(Debug)]
pub enum ResolveError {
    Io(io::Error),
    Wire(WireError),
    Link(LinkError),
    NoNameServers,
    NoSuchResourceRecord,
    DnsError { rcode: u16, query: String },
    UnsupportedFamily(i32),
    Protocol(&'static str),
}

impl ResolveError {
    pub fn varlink_id(&self) -> &'static str {
        match self {
            Self::NoNameServers => "io.systemd.Resolve.NoNameServers",
            Self::NoSuchResourceRecord => "io.systemd.Resolve.NoSuchResourceRecord",
            Self::DnsError { .. } => "io.systemd.Resolve.DNSError",
            Self::UnsupportedFamily(_) => "io.systemd.Resolve.BadAddressSize",
            Self::Link(LinkError::NoSuchLink(_)) => "io.systemd.Resolve.NoSuchLink",
            Self::Link(_) => "io.systemd.Resolve.InvalidParameter",
            Self::Wire(WireError::CnameLoop) => "io.systemd.Resolve.CNAMELoop",
            Self::Io(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                "io.systemd.Resolve.QueryTimedOut"
            }
            _ => "io.systemd.Resolve.MaxAttemptsReached",
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Link(error) => write!(formatter, "{error}"),
            Self::NoNameServers => formatter.write_str("no DNS name servers are configured"),
            Self::NoSuchResourceRecord => formatter.write_str("no such DNS resource record"),
            Self::DnsError { rcode, query } => {
                write!(formatter, "DNS response code {rcode} for {query}")
            }
            Self::UnsupportedFamily(family) => {
                write!(formatter, "unsupported address family {family}")
            }
            Self::Protocol(message) => write!(formatter, "DNS protocol error: {message}"),
        }
    }
}

impl Error for ResolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Link(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ResolveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<WireError> for ResolveError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<LinkError> for ResolveError {
    fn from(error: LinkError) -> Self {
        Self::Link(error)
    }
}