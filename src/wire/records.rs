// SPDX-License-Identifier: LGPL-2.1-or-later
const MAX_CNAME_CHAIN: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressRecords {
    pub addresses: Vec<IpAddr>,
    pub canonical_name: String,
}

#[derive(Default)]
struct AddressAnswerSet {
    aliases: std::collections::HashMap<Vec<u8>, DnsName>,
    addresses: std::collections::HashMap<Vec<u8>, Vec<IpAddr>>,
}

pub fn extract_answer_records(packet: &[u8]) -> Result<Vec<AnswerRecord>, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.question_count {
        offset = parse_question(packet, offset)?.next_offset;
    }

    let mut output = Vec::with_capacity(usize::from(header.answer_count));
    for _ in 0..header.answer_count {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;

        let mut raw = Vec::with_capacity(
            record.name.canonical_wire().len() + 10 + record.rdata.len(),
        );
        raw.extend_from_slice(record.name.canonical_wire());
        raw.extend_from_slice(&record.rr_type.to_be_bytes());
        raw.extend_from_slice(&record.class.to_be_bytes());
        raw.extend_from_slice(&record.ttl.to_be_bytes());
        raw.extend_from_slice(
            &u16::try_from(record.rdata.len())
                .map_err(|_| WireError::InvalidRecord)?
                .to_be_bytes(),
        );
        raw.extend_from_slice(&record.rdata);

        output.push(AnswerRecord {
            name: record.name,
            rr_type: record.rr_type,
            class: record.class,
            ttl: record.ttl,
            raw,
        });
    }
    Ok(output)
}

pub fn extract_service_records(packet: &[u8]) -> Result<ServiceRecords, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.question_count {
        offset = parse_question(packet, offset)?.next_offset;
    }

    let mut output = ServiceRecords::default();
    for _ in 0..header.answer_count {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        if record.class != CLASS_IN {
            continue;
        }

        match record.rr_type {
            TYPE_SRV => {
                if record.rdata.len() < 7 {
                    return Err(WireError::InvalidRecord);
                }
                let target_offset = checked_end(record.rdata_offset, 6)?;
                let (target, target_end) = read_name(packet, target_offset)?;
                if target_end != record.next_offset {
                    return Err(WireError::InvalidRecord);
                }
                output.srv.push(SrvRecord {
                    priority: read_u16(packet, record.rdata_offset)?,
                    weight: read_u16(packet, record.rdata_offset + 2)?,
                    port: read_u16(packet, record.rdata_offset + 4)?,
                    target,
                });
            }
            TYPE_TXT => {
                let mut cursor = record.rdata_offset;
                while cursor < record.next_offset {
                    let length = usize::from(
                        *packet.get(cursor).ok_or(WireError::ShortPacket)?,
                    );
                    cursor = checked_end(cursor, 1)?;
                    let end = checked_end(cursor, length)?;
                    let item = packet
                        .get(cursor..end)
                        .filter(|_| end <= record.next_offset)
                        .ok_or(WireError::InvalidRecord)?;
                    if !item.is_empty() {
                        output.txt.push(item.to_vec());
                    }
                    cursor = end;
                }
            }
            _ => {}
        }
    }
    Ok(output)
}

pub fn extract_address_records(
    packet: &[u8],
    family: Option<i32>,
) -> Result<AddressRecords, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    if header.question_count != 1 {
        return Err(WireError::WrongQuestionCount(header.question_count));
    }
    let question = parse_question(packet, DNS_HEADER_LEN)?;
    let answers = parse_address_answers(packet, header.answer_count, question.next_offset)?;
    resolve_address_chain(&question.name, answers, family)
}

fn parse_address_answers(
    packet: &[u8],
    answer_count: u16,
    mut offset: usize,
) -> Result<AddressAnswerSet, WireError> {
    let mut output = AddressAnswerSet::default();
    for _ in 0..answer_count {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        if record.class != CLASS_IN {
            continue;
        }
        let owner = record.name.canonical_wire().to_vec();
        match record.rr_type {
            TYPE_CNAME => insert_alias(packet, &record, owner, &mut output)?,
            TYPE_A => {
                let [a, b, c, d] = record.rdata.as_slice() else {
                    return Err(WireError::InvalidRecord);
                };
                insert_address(
                    &mut output,
                    owner,
                    IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                );
            }
            TYPE_AAAA => {
                let bytes: [u8; 16] = record
                    .rdata
                    .as_slice()
                    .try_into()
                    .map_err(|_| WireError::InvalidRecord)?;
                insert_address(&mut output, owner, IpAddr::V6(Ipv6Addr::from(bytes)));
            }
            _ => {}
        }
    }
    if output
        .aliases
        .keys()
        .any(|owner| output.addresses.contains_key(owner))
    {
        return Err(WireError::InvalidRecord);
    }
    Ok(output)
}

fn insert_alias(
    packet: &[u8],
    record: &ResourceRecord,
    owner: Vec<u8>,
    output: &mut AddressAnswerSet,
) -> Result<(), WireError> {
    let (target, end) = read_name(packet, record.rdata_offset)?;
    if end != record.next_offset {
        return Err(WireError::InvalidRecord);
    }
    if let Some(existing) = output.aliases.get(&owner) {
        if existing.canonical_wire() != target.canonical_wire() {
            return Err(WireError::InvalidRecord);
        }
    } else {
        output.aliases.insert(owner, target);
    }
    Ok(())
}

fn insert_address(output: &mut AddressAnswerSet, owner: Vec<u8>, address: IpAddr) {
    let values = output.addresses.entry(owner).or_default();
    if !values.contains(&address) {
        values.push(address);
    }
}

fn resolve_address_chain(
    question: &DnsName,
    mut answers: AddressAnswerSet,
    family: Option<i32>,
) -> Result<AddressRecords, WireError> {
    let mut current = question.canonical_wire().to_vec();
    let mut canonical_name = question.text().to_owned();
    let mut visited = std::collections::HashSet::new();
    for _ in 0..MAX_CNAME_CHAIN {
        if !visited.insert(current.clone()) {
            return Err(WireError::InvalidRecord);
        }
        let Some(target) = answers.aliases.get(&current) else {
            let addresses = answers
                .addresses
                .remove(&current)
                .unwrap_or_default()
                .into_iter()
                .filter(|address| family_matches(family, address))
                .collect();
            return Ok(AddressRecords {
                addresses,
                canonical_name,
            });
        };
        target.text().clone_into(&mut canonical_name);
        current = target.canonical_wire().to_vec();
    }
    Err(WireError::InvalidRecord)
}

fn family_matches(family: Option<i32>, address: &IpAddr) -> bool {
    matches!(
        (family, address),
        (None, _) | (Some(2), IpAddr::V4(_)) | (Some(10), IpAddr::V6(_))
    )
}

pub fn extract_addresses(
    packet: &[u8],
    family: Option<i32>,
) -> Result<Vec<IpAddr>, WireError> {
    Ok(extract_address_records(packet, family)?.addresses)
}

pub fn extract_ptr_names(packet: &[u8]) -> Result<Vec<String>, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.question_count {
        offset = parse_question(packet, offset)?.next_offset;
    }

    let mut output = Vec::new();
    for _ in 0..header.answer_count {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        if record.class == CLASS_IN && record.rr_type == TYPE_PTR {
            output.push(read_name(packet, record.rdata_offset)?.0.text().to_owned());
        }
    }
    Ok(output)
}

pub fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(address) => {
            let mut output = String::new();
            for byte in address.octets().iter().rev() {
                use std::fmt::Write as _;
                let _ = write!(output, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
            }
            output.push_str("ip6.arpa");
            output
        }
    }
}

pub fn parse_reverse_name(name: &str) -> Option<IpAddr> {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(prefix) = lower.strip_suffix(".in-addr.arpa") {
        let octets: Vec<u8> = prefix
            .split('.')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        if let [d, c, b, a] = octets.as_slice() {
            return Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)));
        }
        return None;
    }

    if let Some(prefix) = lower.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<u8> = prefix
            .split('.')
            .map(|nibble| u8::from_str_radix(nibble, 16))
            .collect::<Result<_, _>>()
            .ok()?;
        if nibbles.len() != 32 || nibbles.iter().any(|nibble| *nibble > 0x0f) {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, pair) in nibbles.chunks_exact(2).enumerate() {
            bytes[15 - index] = pair[0] | (pair[1] << 4);
        }
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    None
}
