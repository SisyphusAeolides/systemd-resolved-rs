// SPDX-License-Identifier: LGPL-2.1-or-later
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

pub fn extract_addresses(
    packet: &[u8],
    family: Option<i32>,
) -> Result<Vec<IpAddr>, WireError> {
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
        if record.class != CLASS_IN {
            continue;
        }
        match (record.rr_type, record.rdata.as_slice(), family) {
            (TYPE_A, [a, b, c, d], None | Some(2)) => {
                output.push(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)));
            }
            (TYPE_AAAA, bytes, None | Some(10)) if bytes.len() == 16 => {
                let mut address = [0; 16];
                address.copy_from_slice(bytes);
                output.push(IpAddr::V6(Ipv6Addr::from(address)));
            }
            _ => {}
        }
    }
    Ok(output)
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
