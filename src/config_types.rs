// SPDX-License-Identifier: LGPL-2.1-or-later
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportMode {
    No,
    Resolve,
    Yes,
}

impl SupportMode {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "no" | "false" | "off" | "0" => Ok(Self::No),
            "resolve" => Ok(Self::Resolve),
            "yes" | "true" | "on" | "1" => Ok(Self::Yes),
            other => Err(ConfigError::InvalidValue(other.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationMode {
    No,
    AllowDowngrade,
    Yes,
}

impl ValidationMode {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "no" | "false" | "off" | "0" => Ok(Self::No),
            "allow-downgrade" => Ok(Self::AllowDowngrade),
            "yes" | "true" | "on" | "1" => Ok(Self::Yes),
            other => Err(ConfigError::InvalidValue(other.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMode {
    No,
    Opportunistic,
    Yes,
}

impl TlsMode {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "no" | "false" | "off" | "0" => Ok(Self::No),
            "opportunistic" => Ok(Self::Opportunistic),
            "yes" | "true" | "on" | "1" => Ok(Self::Yes),
            other => Err(ConfigError::InvalidValue(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Domain {
    pub name: String,
    pub route_only: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ConfigAssignments {
    dns: bool,
    domains: bool,
}

impl ConfigAssignments {
    fn merge(&mut self, other: Self) {
        self.dns |= other.dns;
        self.domains |= other.domains;
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    pub upstreams: Vec<SocketAddr>,
    pub fallback_upstreams: Vec<SocketAddr>,
    pub listeners: Vec<SocketAddr>,
    pub proxy_listeners: Vec<SocketAddr>,
    pub domains: Vec<Domain>,
    pub varlink_path: PathBuf,
    pub runtime_directory: PathBuf,
    pub hosts_path: PathBuf,
    pub cache: bool,
    pub cache_size: usize,
    pub cache_max_ttl: Duration,
    pub stale_retention: Duration,
    pub query_timeout: Duration,
    pub attempts: usize,
    pub workers: usize,
    pub read_etc_hosts: bool,
    pub read_static_records: bool,
    pub resolve_unicast_single_label: bool,
    pub llmnr: SupportMode,
    pub multicast_dns: SupportMode,
    pub dnssec: ValidationMode,
    pub dns_over_tls: TlsMode,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            fallback_upstreams: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
            ],
            listeners: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
                53,
            )],
            proxy_listeners: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 54)),
                53,
            )],
            domains: Vec::new(),
            varlink_path: PathBuf::from("/run/systemd/resolve/io.systemd.Resolve"),
            runtime_directory: PathBuf::from("/run/systemd/resolve"),
            hosts_path: PathBuf::from("/etc/hosts"),
            cache: true,
            cache_size: 4096,
            cache_max_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            stale_retention: Duration::ZERO,
            query_timeout: Duration::from_secs(5),
            attempts: 3,
            workers: 4,
            read_etc_hosts: true,
            read_static_records: true,
            resolve_unicast_single_label: false,
            llmnr: SupportMode::Yes,
            multicast_dns: SupportMode::Yes,
            dnssec: ValidationMode::AllowDowngrade,
            dns_over_tls: TlsMode::No,
        }
    }
}

