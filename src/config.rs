// SPDX-License-Identifier: LGPL-2.1-or-later
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

#[derive(Clone, Debug)]
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
            resolve_unicast_single_label: false,
            llmnr: SupportMode::Yes,
            multicast_dns: SupportMode::Yes,
            dnssec: ValidationMode::AllowDowngrade,
            dns_over_tls: TlsMode::No,
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let mut config = Self::default();
        apply_optional_file(&mut config, path)?;
        for drop_in in discover_drop_ins(path)? {
            apply_optional_file(&mut config, &drop_in)?;
        }
        if config.upstreams.is_empty() {
            config.upstreams = discover_resolv_conf(Path::new("/etc/resolv.conf"))?;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn apply_text(&mut self, text: &str) -> Result<(), ConfigError> {
        let mut resolve_section = false;
        for (index, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                resolve_section = &line[1..line.len() - 1] == "Resolve";
                continue;
            }
            if !resolve_section {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| ConfigError::Line {
                line: index + 1,
                message: "expected key=value".to_owned(),
            })?;
            self.apply_setting(key.trim(), value.trim())
                .map_err(|error| ConfigError::Line {
                    line: index + 1,
                    message: error.to_string(),
                })?;
        }
        self.validate()
    }

    fn apply_setting(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        match key {
            "DNS" => apply_server_assignment(&mut self.upstreams, value)?,
            "FallbackDNS" => apply_server_assignment(&mut self.fallback_upstreams, value)?,
            "Domains" => apply_domain_assignment(&mut self.domains, value)?,
            "Cache" => self.cache = parse_cache_mode(value)?,
            "DNSCacheSize" => {
                self.cache_size = value
                    .parse()
                    .map_err(|_| ConfigError::InvalidValue(value.to_owned()))?;
            }
            "CacheMaxTTL" | "CacheMaxTTLSec" => {
                self.cache_max_ttl = parse_duration(value)?;
            }
            "StaleRetentionSec" => self.stale_retention = parse_duration(value)?,
            "QueryTimeoutSec" => self.query_timeout = parse_duration(value)?,
            "Attempts" => {
                self.attempts = value
                    .parse()
                    .map_err(|_| ConfigError::InvalidValue(value.to_owned()))?;
            }
            "Workers" => {
                self.workers = value
                    .parse()
                    .map_err(|_| ConfigError::InvalidValue(value.to_owned()))?;
            }
            "LLMNR" => self.llmnr = SupportMode::parse(value)?,
            "MulticastDNS" => self.multicast_dns = SupportMode::parse(value)?,
            "DNSSEC" => self.dnssec = ValidationMode::parse(value)?,
            "DNSOverTLS" => self.dns_over_tls = TlsMode::parse(value)?,
            "ReadEtcHosts" => self.read_etc_hosts = parse_bool(value)?,
            "ResolveUnicastSingleLabel" => {
                self.resolve_unicast_single_label = parse_bool(value)?;
            }
            "DNSStubListener" => match value.to_ascii_lowercase().as_str() {
                "no" | "false" | "off" | "0" => {
                    self.listeners.clear();
                    self.proxy_listeners.clear();
                }
                "yes" | "true" | "on" | "1" | "udp" | "tcp" => {}
                _ => return Err(ConfigError::InvalidValue(value.to_owned())),
            },
            _ => {}
        }
        Ok(())
    }

    pub fn effective_upstreams(&self) -> Vec<SocketAddr> {
        let source = if self.upstreams.is_empty() {
            &self.fallback_upstreams
        } else {
            &self.upstreams
        };
        let mut output = Vec::new();
        for server in source {
            if !is_local_stub(*server) && !output.contains(server) {
                output.push(*server);
            }
        }
        output
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.attempts == 0 || self.attempts > 32 {
            return Err(ConfigError::InvalidValue(
                "Attempts must be between 1 and 32".to_owned(),
            ));
        }
        if self.workers == 0 || self.workers > 4096 {
            return Err(ConfigError::InvalidValue(
                "Workers must be between 1 and 4096".to_owned(),
            ));
        }
        if self.query_timeout.is_zero() {
            return Err(ConfigError::InvalidValue(
                "QueryTimeoutSec must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn write_runtime_resolv_confs(&self) -> Result<(), ConfigError> {
        fs::create_dir_all(&self.runtime_directory)?;
        let search_domains: Vec<&str> = self
            .domains
            .iter()
            .filter(|domain| !domain.route_only && domain.name != ".")
            .map(|domain| domain.name.as_str())
            .collect();

        let mut stub = String::from(
            "# This file is managed by systemd-resolved-rs.\n\
             nameserver 127.0.0.53\n\
             options edns0 trust-ad\n",
        );
        if !search_domains.is_empty() {
            stub.push_str("search ");
            stub.push_str(&search_domains.join(" "));
            stub.push('\n');
        }
        atomic_write(&self.runtime_directory.join("stub-resolv.conf"), &stub)?;

        let mut uplink = String::from("# This file is managed by systemd-resolved-rs.\n");
        for server in self.effective_upstreams() {
            uplink.push_str("nameserver ");
            uplink.push_str(&server.ip().to_string());
            uplink.push('\n');
        }
        if !search_domains.is_empty() {
            uplink.push_str("search ");
            uplink.push_str(&search_domains.join(" "));
            uplink.push('\n');
        }
        atomic_write(&self.runtime_directory.join("resolv.conf"), &uplink)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    InvalidServer(String),
    InvalidValue(String),
    Line { line: usize, message: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::InvalidServer(server) => write!(formatter, "invalid DNS server: {server}"),
            Self::InvalidValue(value) => write!(formatter, "invalid value: {value}"),
            Self::Line { line, message } => write!(formatter, "line {line}: {message}"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Self::Io(error) = self {
            Some(error)
        } else {
            None
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn apply_optional_file(config: &mut Config, path: &Path) -> Result<(), ConfigError> {
    match fs::read_to_string(path) {
        Ok(text) => config.apply_text(&text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ConfigError::Io(error)),
    }
}

fn discover_drop_ins(main: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let mut selected = BTreeMap::<String, PathBuf>::new();
    let mut directories = Vec::new();
    if main == Path::new("/etc/systemd/resolved.conf") {
        directories.extend([
            PathBuf::from("/usr/lib/systemd/resolved.conf.d"),
            PathBuf::from("/usr/local/lib/systemd/resolved.conf.d"),
            PathBuf::from("/run/systemd/resolved.conf.d"),
            PathBuf::from("/etc/systemd/resolved.conf.d"),
        ]);
    } else if let Some(parent) = main.parent() {
        directories.push(parent.join("resolved.conf.d"));
    }

    for directory in directories {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(ConfigError::Io(error)),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("conf") {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                selected.insert(name.to_owned(), path);
            }
        }
    }
    Ok(selected.into_values().collect())
}

fn apply_server_assignment(
    destination: &mut Vec<SocketAddr>,
    value: &str,
) -> Result<(), ConfigError> {
    if value.is_empty() {
        destination.clear();
        return Ok(());
    }
    for server in value.split_whitespace().map(parse_server) {
        let server = server?;
        if !destination.contains(&server) {
            destination.push(server);
        }
    }
    Ok(())
}

fn apply_domain_assignment(destination: &mut Vec<Domain>, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        destination.clear();
        return Ok(());
    }
    for token in value.split_whitespace() {
        let route_only = token.starts_with('~');
        let name = token.trim_start_matches('~').trim_end_matches('.');
        let name = if name.is_empty() { "." } else { name };
        if !name.is_ascii() || name.split('.').any(|label| label.len() > 63) {
            return Err(ConfigError::InvalidValue(token.to_owned()));
        }
        let domain = Domain {
            name: name.to_ascii_lowercase(),
            route_only,
        };
        if !destination.contains(&domain) {
            destination.push(domain);
        }
    }
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Ok(true),
        "no" | "false" | "off" | "0" => Ok(false),
        _ => Err(ConfigError::InvalidValue(value.to_owned())),
    }
}

fn parse_cache_mode(value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" | "no-negative" => Ok(true),
        "no" | "false" | "off" | "0" => Ok(false),
        _ => Err(ConfigError::InvalidValue(value.to_owned())),
    }
}

fn parse_duration(value: &str) -> Result<Duration, ConfigError> {
    let value = value.trim();
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 0.001)
    } else if let Some(number) = value.strip_suffix("min") {
        (number, 60.0)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3600.0)
    } else if let Some(number) = value.strip_suffix('d') {
        (number, 86_400.0)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1.0)
    } else {
        (value, 1.0)
    };
    let number: f64 = number
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidValue(value.to_owned()))?;
    if !number.is_finite() || number < 0.0 {
        return Err(ConfigError::InvalidValue(value.to_owned()));
    }
    Duration::try_from_secs_f64(number * multiplier)
        .map_err(|_| ConfigError::InvalidValue(value.to_owned()))
}

pub fn parse_server(value: &str) -> Result<SocketAddr, ConfigError> {
    let mut host = value.trim();
    if let Some((address, _server_name)) = host.split_once('#') {
        host = address;
    }
    if let Some((address, _interface)) = host.split_once('%') {
        host = address;
    }
    if let Ok(address) = host.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, 53));
    }
    Err(ConfigError::InvalidServer(value.to_owned()))
}

pub fn discover_resolv_conf(path: &Path) -> Result<Vec<SocketAddr>, ConfigError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(ConfigError::Io(error)),
    };
    let mut output = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(value) = fields.next() else {
            continue;
        };
        let server = parse_server(value)?;
        if !is_local_stub(server) && !output.contains(&server) {
            output.push(server);
        }
    }
    Ok(output)
}

fn is_local_stub(server: SocketAddr) -> bool {
    match server.ip() {
        IpAddr::V4(address) => {
            address == Ipv4Addr::new(127, 0, 0, 53) || address == Ipv4Addr::new(127, 0, 0, 54)
        }
        IpAddr::V6(address) => address.is_loopback(),
    }
}

fn atomic_write(path: &Path, contents: &str) -> Result<(), ConfigError> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, contents)?;
    fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_resolved_settings() {
        let mut config = Config::default();
        config
            .apply_text(
                "[Resolve]\n\
                 DNS=192.0.2.53 2001:db8::53\n\
                 Domains=example.test ~corp.test\n\
                 Cache=no\n\
                 DNSCacheSize=128\n\
                 ReadEtcHosts=no\n",
            )
            .expect("configuration");
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.domains.len(), 2);
        assert!(!config.cache);
        assert_eq!(config.cache_size, 128);
        assert!(!config.read_etc_hosts);
    }

    #[test]
    fn empty_assignment_resets_a_list() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nDNS=192.0.2.53\nDNS=\n")
            .expect("configuration");
        assert!(config.upstreams.is_empty());
    }

    #[test]
    fn local_stub_is_not_an_upstream() {
        let config = Config {
            upstreams: vec![
                "127.0.0.53:53".parse().expect("stub"),
                "192.0.2.53:53".parse().expect("uplink"),
            ],
            ..Config::default()
        };
        assert_eq!(config.effective_upstreams().len(), 1);
    }
}
