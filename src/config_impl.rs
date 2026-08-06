// SPDX-License-Identifier: LGPL-2.1-or-later
impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let mut config = Self::default();
        let mut assignments = apply_optional_file(&mut config, path)?;
        for drop_in in discover_drop_ins(path)? {
            assignments.merge(apply_optional_file(&mut config, &drop_in)?);
        }

        let may_read_external_configuration = !assignments.dns && !assignments.domains;
        let credentials_present = may_read_external_configuration
            && apply_credentials_from_environment(&mut config);
        if may_read_external_configuration && !credentials_present && config.upstreams.is_empty() {
            config.upstreams = discover_resolv_conf(Path::new("/etc/resolv.conf"))?;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn apply_text(&mut self, text: &str) -> Result<(), ConfigError> {
        self.apply_text_tracking(text)?;
        Ok(())
    }

    fn apply_text_tracking(&mut self, text: &str) -> Result<ConfigAssignments, ConfigError> {
        let mut assignments = ConfigAssignments::default();
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
            let key = key.trim();
            self.apply_setting(key, value.trim())
                .map_err(|error| ConfigError::Line {
                    line: index + 1,
                    message: error.to_string(),
                })?;
            match key {
                "DNS" => assignments.dns = true,
                "Domains" => assignments.domains = true,
                _ => {}
            }
        }
        self.validate()?;
        Ok(assignments)
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
            "ReadStaticRecords" => self.read_static_records = parse_bool(value)?,
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

    pub fn configured_upstreams(&self) -> Vec<SocketAddr> {
        filtered_servers(&self.upstreams)
    }

    pub fn configured_fallback_upstreams(&self) -> Vec<SocketAddr> {
        filtered_servers(&self.fallback_upstreams)
    }

    pub fn effective_upstreams(&self) -> Vec<SocketAddr> {
        let upstreams = self.configured_upstreams();
        if upstreams.is_empty() {
            self.configured_fallback_upstreams()
        } else {
            upstreams
        }
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

