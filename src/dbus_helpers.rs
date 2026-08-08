// SPDX-License-Identifier: LGPL-2.1-or-later
fn manager_dns_entry(ifindex: i32, server: SocketAddr) -> (i32, i32, Vec<u8>) {
    let (family, address) = address_bytes(server.ip());
    (ifindex, family, address)
}

fn manager_dns_ex(
    servers: &[DnsServerSpec],
    ifindex: i32,
) -> Vec<(i32, i32, Vec<u8>, u16, String)> {
    servers
        .iter()
        .map(|server| manager_dns_ex_entry(ifindex, server))
        .collect()
}

fn manager_dns_ex_entry(
    ifindex: i32,
    server: &DnsServerSpec,
) -> (i32, i32, Vec<u8>, u16, String) {
    let (family, address) = address_bytes(server.address.ip());
    let ifindex = server
        .interface
        .as_deref()
        .and_then(|interface| crate::interface::resolve_ifindex(interface).ok())
        .unwrap_or(ifindex);
    (
        ifindex,
        family,
        address,
        dns_ex_output_port(server.address.port()),
        server.server_name.clone().unwrap_or_default(),
    )
}

fn link_dns_entry(server: SocketAddr) -> (i32, Vec<u8>) {
    address_bytes(server.ip())
}

fn link_dns_ex_entry(server: DnsServerSpec) -> (i32, Vec<u8>, u16, String) {
    let (family, address) = address_bytes(server.address.ip());
    (
        family,
        address,
        dns_ex_output_port(server.address.port()),
        server.server_name.unwrap_or_default(),
    )
}

fn decode_dns_server_specs(
    addresses: Vec<(i32, Vec<u8>, u16, String)>,
) -> Result<Vec<DnsServerSpec>, DbusError> {
    addresses
        .into_iter()
        .map(|(family, address, port, server_name)| {
            Ok(DnsServerSpec {
                address: SocketAddr::new(
                    decode_address(family, &address)?,
                    dns_ex_input_port(port),
                ),
                interface: None,
                server_name: (!server_name.is_empty()).then_some(server_name),
            })
        })
        .collect()
}

const fn dns_ex_input_port(port: u16) -> u16 {
    if matches!(port, 0 | 53 | 853) {
        DNS_PORT
    } else {
        port
    }
}

const fn dns_ex_output_port(port: u16) -> u16 {
    if matches!(port, 53 | 853) {
        0
    } else {
        port
    }
}

fn name_lookup_reply(lookup: NameLookup, ifindex: i32) -> (Vec<(i32, i32, Vec<u8>)>, String, u64) {
    let addresses = lookup
        .addresses
        .into_iter()
        .map(|address| {
            let (family, bytes) = address_bytes(address);
            (ifindex.max(0), family, bytes)
        })
        .collect();
    (
        addresses,
        lookup.canonical_name,
        lookup.flags | SD_RESOLVED_PROTOCOL_DNS,
    )
}

fn address_lookup_reply(lookup: AddressLookup, ifindex: i32) -> (Vec<(i32, String)>, u64) {
    (
        lookup
            .names
            .into_iter()
            .map(|name| (ifindex.max(0), name))
            .collect(),
        lookup.flags | SD_RESOLVED_PROTOCOL_DNS,
    )
}

fn response_flags(response: &[u8]) -> u64 {
    Header::parse(response).map_or(SD_RESOLVED_PROTOCOL_DNS, |header| {
        let authenticated = if header.flags & 0x0020 != 0 {
            1 << 9
        } else {
            0
        };
        SD_RESOLVED_PROTOCOL_DNS | authenticated
    })
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn resolve_service_reply(
    resolver: &Resolver,
    ifindex: i32,
    name: &str,
    service_type: &str,
    domain: &str,
    family: i32,
    flags: u64,
) -> Result<
    (
        Vec<(u16, u16, u16, String, Vec<(i32, i32, Vec<u8>)>, String)>,
        Vec<Vec<u8>>,
        String,
        String,
        String,
        u64,
    ),
    DbusError,
> {
    let (owner, canonical_name, canonical_type, canonical_domain) =
        service_owner(name, service_type, domain)?;
    let mut flags = flags;
    let refused = &resolver.config().refuse_record_types;
    if refused.contains(&TYPE_A) && refused.contains(&TYPE_AAAA) {
        flags |= SD_RESOLVED_NO_ADDRESS;
    }
    if refused.contains(&TYPE_TXT) {
        flags |= SD_RESOLVED_NO_TXT;
    }
    let response = resolver
        .resolve_record_on_link(&owner, CLASS_IN, TYPE_SRV, positive_ifindex(ifindex))
        .map_err(map_resolve_error)?;
    let records = extract_service_records(&response)
        .map_err(|error| DbusError::InvalidReply(error.to_string()))?;
    let mut services = Vec::new();
    let mut root_target = false;
    let mut last_error = None;

    for record in records.srv {
        if record.target.text() == "." {
            root_target = true;
            continue;
        }
        let mut addresses = Vec::new();
        let mut canonical = String::new();
        if flags & SD_RESOLVED_NO_ADDRESS == 0 {
            match resolver.lookup_name_on_link(
                record.target.text(),
                family,
                positive_ifindex(ifindex),
            ) {
                Ok(lookup) => {
                    canonical = lookup.canonical_name;
                    addresses = lookup
                        .addresses
                        .into_iter()
                        .map(|address| {
                            let (family, bytes) = address_bytes(address);
                            (ifindex.max(0), family, bytes)
                        })
                        .collect();
                }
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            }
        }
        services.push((
            record.priority,
            record.weight,
            record.port,
            record.target.text().to_owned(),
            addresses,
            canonical,
        ));
    }

    if services.is_empty() {
        if root_target {
            return Err(DbusError::NoSuchService(
                "service is explicitly not provided".to_owned(),
            ));
        }
        if let Some(error) = last_error {
            return Err(map_resolve_error(error));
        }
        return Err(DbusError::NoSuchService("service was not found".to_owned()));
    }

    let txt_data = if flags & SD_RESOLVED_NO_TXT != 0 {
        Vec::new()
    } else {
        match resolver.resolve_record_on_link(&owner, CLASS_IN, TYPE_TXT, positive_ifindex(ifindex))
        {
            Ok(response) => {
                extract_service_records(&response)
                    .map_err(|error| DbusError::InvalidReply(error.to_string()))?
                    .txt
            }
            Err(ResolveError::NoSuchResourceRecord) => Vec::new(),
            Err(error) => return Err(map_resolve_error(error)),
        }
    };

    Ok((
        services,
        txt_data,
        canonical_name,
        canonical_type,
        canonical_domain,
        response_flags(&response),
    ))
}

fn service_owner(
    name: &str,
    service_type: &str,
    domain: &str,
) -> Result<(String, String, String, String), DbusError> {
    let name = name.trim_end_matches('.');
    let service_type = service_type.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() || !service_type_is_valid(service_type) {
        return Err(DbusError::InvalidArgs(
            "invalid service type or domain".to_owned(),
        ));
    }
    if !name.is_empty() && !service_instance_is_valid(name) {
        return Err(DbusError::InvalidArgs(
            "invalid service instance name".to_owned(),
        ));
    }
    let owner = if name.is_empty() {
        format!("{service_type}.{domain}")
    } else {
        format!("{name}.{service_type}.{domain}")
    };
    Ok((
        owner,
        name.to_owned(),
        service_type.to_ascii_lowercase(),
        domain.to_ascii_lowercase(),
    ))
}

fn service_instance_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.is_ascii()
        && !value.bytes().any(|byte| matches!(byte, b'.' | 0))
}

fn service_type_is_valid(value: &str) -> bool {
    let mut labels = value.split('.');
    let Some(service) = labels.next() else {
        return false;
    };
    let Some(protocol) = labels.next() else {
        return false;
    };
    labels.next().is_none() && valid_service_label(service) && valid_service_label(protocol)
}

fn valid_service_label(value: &str) -> bool {
    value.starts_with('_')
        && value.len() > 1
        && value.len() <= 63
        && value.is_ascii()
        && value
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn parse_support_mode(value: &str) -> Result<SupportMode, DbusError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "yes" | "true" | "on" | "1" => Ok(SupportMode::Yes),
        "resolve" => Ok(SupportMode::Resolve),
        "no" | "false" | "off" | "0" => Ok(SupportMode::No),
        _ => Err(DbusError::InvalidArgs(format!(
            "invalid resolver support mode {value}"
        ))),
    }
}

fn parse_tls_mode(value: &str) -> Result<TlsMode, DbusError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "no" | "false" | "off" | "0" => Ok(TlsMode::No),
        "opportunistic" => Ok(TlsMode::Opportunistic),
        "yes" | "true" | "on" | "1" => Ok(TlsMode::Yes),
        _ => Err(DbusError::InvalidArgs(format!(
            "invalid DNS-over-TLS mode {value}"
        ))),
    }
}

fn parse_validation_mode(value: &str) -> Result<ValidationMode, DbusError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "allow-downgrade" => Ok(ValidationMode::AllowDowngrade),
        "no" | "false" | "off" | "0" => Ok(ValidationMode::No),
        "yes" | "true" | "on" | "1" => Ok(ValidationMode::Yes),
        _ => Err(DbusError::InvalidArgs(format!(
            "invalid DNSSEC mode {value}"
        ))),
    }
}

const fn support_mode_string(mode: SupportMode) -> &'static str {
    match mode {
        SupportMode::No => "no",
        SupportMode::Resolve => "resolve",
        SupportMode::Yes => "yes",
    }
}

const fn tls_mode_string(mode: TlsMode) -> &'static str {
    match mode {
        TlsMode::No => "no",
        TlsMode::Opportunistic => "opportunistic",
        TlsMode::Yes => "yes",
    }
}

const fn validation_mode_string(mode: ValidationMode) -> &'static str {
    match mode {
        ValidationMode::No => "no",
        ValidationMode::AllowDowngrade => "allow-downgrade",
        ValidationMode::Yes => "yes",
    }
}

fn map_link_error(error: LinkError) -> DbusError {
    match error {
        LinkError::NoSuchLink(_) | LinkError::InvalidIfindex(_) => {
            DbusError::NoSuchLink(error.to_string())
        }
        LinkError::ManagedLink(_) => DbusError::LinkBusy(error.to_string()),
        LinkError::InvalidDomain(_) => DbusError::InvalidArgs(error.to_string()),
    }
}

fn map_resolve_error(error: ResolveError) -> DbusError {
    match error {
        ResolveError::NoNameServers => DbusError::NoNameServers(error.to_string()),
        ResolveError::NoSuchResourceRecord => DbusError::NoSuchResourceRecord(error.to_string()),
        ResolveError::Link(link) => map_link_error(link),
        ResolveError::UnsupportedFamily(_) => DbusError::InvalidArgs(error.to_string()),
        ResolveError::Io(_) => DbusError::NetworkDown(error.to_string()),
        ResolveError::Wire(crate::wire::WireError::CnameLoop) => {
            DbusError::CNameLoop(error.to_string())
        }
        ResolveError::DnsError { rcode, .. } => dns_rcode_error(rcode, error.to_string()),
        ResolveError::QueryRefused => DbusError::DnsRefused(error.to_string()),
        ResolveError::ResourceRecordTypeObsolete => {
            DbusError::ResourceRecordTypeUnsupported(error.to_string())
        }
        ResolveError::QueryAborted => DbusError::NetworkDown(error.to_string()),
        ResolveError::DnssecValidationFailed { .. }
        | ResolveError::NoTrustAnchor
        | ResolveError::InconsistentServiceRecords
        | ResolveError::StubLoop
        | ResolveError::Wire(_)
        | ResolveError::Protocol(_) => DbusError::InvalidReply(error.to_string()),
    }
}

fn dns_rcode_error(rcode: u16, message: String) -> DbusError {
    match rcode {
        1 => DbusError::DnsFormErr(message),
        2 => DbusError::DnsServFail(message),
        3 => DbusError::DnsNxDomain(message),
        4 => DbusError::DnsNotImp(message),
        5 => DbusError::DnsRefused(message),
        6 => DbusError::DnsYxDomain(message),
        7 => DbusError::DnsYrrset(message),
        8 => DbusError::DnsNxrrset(message),
        9 => DbusError::DnsNotAuth(message),
        10 => DbusError::DnsNotZone(message),
        16 => DbusError::DnsBadVers(message),
        17 => DbusError::DnsBadKey(message),
        18 => DbusError::DnsBadTime(message),
        19 => DbusError::DnsBadMode(message),
        20 => DbusError::DnsBadName(message),
        21 => DbusError::DnsBadAlg(message),
        22 => DbusError::DnsBadTrunc(message),
        23 => DbusError::DnsBadCookie(message),
        _ => DbusError::InvalidReply(message),
    }
}
