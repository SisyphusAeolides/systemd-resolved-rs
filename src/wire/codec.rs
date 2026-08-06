// SPDX-License-Identifier: LGPL-2.1-or-later
fn checked_end(offset: usize, length: usize) -> Result<usize, WireError> {
    offset.checked_add(length).ok_or(WireError::ShortPacket)
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, WireError> {
    let end = checked_end(offset, 2)?;
    let bytes = packet.get(offset..end).ok_or(WireError::ShortPacket)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, WireError> {
    let end = checked_end(offset, 4)?;
    let bytes = packet.get(offset..end).ok_or(WireError::ShortPacket)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u16(packet: &mut [u8], offset: usize, value: u16) -> Result<(), WireError> {
    let end = checked_end(offset, 2)?;
    packet
        .get_mut(offset..end)
        .ok_or(WireError::ShortPacket)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u32(packet: &mut [u8], offset: usize, value: u32) -> Result<(), WireError> {
    let end = checked_end(offset, 4)?;
    packet
        .get_mut(offset..end)
        .ok_or(WireError::ShortPacket)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn display_label(label: &[u8]) -> String {
    let mut output = String::new();
    for &byte in label {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {
                output.push(char::from(byte));
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\{byte:03}");
            }
        }
    }
    output
}

pub fn read_name(packet: &[u8], offset: usize) -> Result<(DnsName, usize), WireError> {
    if offset >= packet.len() {
        return Err(WireError::ShortPacket);
    }

    let mut cursor = offset;
    let mut next_offset = offset;
    let mut jumped = false;
    let mut pointer_steps = 0usize;
    let mut expanded_length = 1usize;
    let mut labels = Vec::new();
    let mut canonical_wire = Vec::new();

    loop {
        let length = *packet.get(cursor).ok_or(WireError::ShortPacket)?;
        if length == 0 {
            if !jumped {
                next_offset = cursor + 1;
            }
            canonical_wire.push(0);
            break;
        }

        if length & 0xc0 == 0xc0 {
            let second = *packet.get(cursor + 1).ok_or(WireError::ShortPacket)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if pointer >= cursor || pointer >= packet.len() {
                return Err(WireError::CompressionLoop);
            }
            pointer_steps += 1;
            if pointer_steps > 128 {
                return Err(WireError::CompressionLoop);
            }
            if !jumped {
                next_offset = cursor + 2;
                jumped = true;
            }
            cursor = pointer;
            continue;
        }

        if length & 0xc0 != 0 || length > 63 {
            return Err(WireError::InvalidLabel);
        }

        let label_length = usize::from(length);
        let start = cursor + 1;
        let end = checked_end(start, label_length)?;
        let label = packet.get(start..end).ok_or(WireError::ShortPacket)?;
        expanded_length = expanded_length
            .checked_add(label_length + 1)
            .ok_or(WireError::NameTooLong)?;
        if expanded_length > 255 {
            return Err(WireError::NameTooLong);
        }

        canonical_wire.push(length);
        canonical_wire.extend(label.iter().map(u8::to_ascii_lowercase));
        labels.push(display_label(label));
        cursor = end;
        if !jumped {
            next_offset = cursor;
        }
    }

    let text = if labels.is_empty() {
        ".".to_owned()
    } else {
        labels.join(".")
    };
    Ok((
        DnsName {
            text,
            canonical_wire,
        },
        next_offset,
    ))
}

pub fn encode_name(name: &str) -> Result<Vec<u8>, WireError> {
    let stripped = name.strip_suffix('.').unwrap_or(name);
    if stripped.is_empty() {
        return Ok(vec![0]);
    }
    if !stripped.is_ascii() {
        return Err(WireError::InvalidName(name.to_owned()));
    }

    let mut output = Vec::new();
    for label in stripped.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(WireError::InvalidName(name.to_owned()));
        }
        output.push(u8::try_from(label.len()).map_err(|_| WireError::NameTooLong)?);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    if output.len() > 255 {
        Err(WireError::NameTooLong)
    } else {
        Ok(output)
    }
}

pub fn parse_question(packet: &[u8], offset: usize) -> Result<Question, WireError> {
    let (name, offset) = read_name(packet, offset)?;
    let rr_type = read_u16(packet, offset)?;
    let class = read_u16(packet, offset + 2)?;
    Ok(Question {
        name,
        rr_type,
        class,
        next_offset: offset + 4,
    })
}

pub fn parse_record(packet: &[u8], offset: usize) -> Result<ResourceRecord, WireError> {
    let (name, offset) = read_name(packet, offset)?;
    let rr_type = read_u16(packet, offset)?;
    let class = read_u16(packet, offset + 2)?;
    let ttl_offset = offset + 4;
    let ttl = read_u32(packet, ttl_offset)?;
    let rdata_length = usize::from(read_u16(packet, offset + 8)?);
    let rdata_offset = offset + 10;
    let next_offset = checked_end(rdata_offset, rdata_length)?;
    let rdata = packet
        .get(rdata_offset..next_offset)
        .ok_or(WireError::ShortPacket)?
        .to_vec();
    Ok(ResourceRecord {
        name,
        rr_type,
        class,
        ttl,
        ttl_offset,
        rdata_offset,
        rdata,
        next_offset,
    })
}

fn parse_sections(
    packet: &[u8],
) -> Result<(Header, Vec<Question>, Vec<ResourceRecord>, usize), WireError> {
    let header = Header::parse(packet)?;
    let mut offset = DNS_HEADER_LEN;
    let question_capacity = usize::from(header.question_count).min(packet.len() / 5);
    let mut questions = Vec::with_capacity(question_capacity);
    for _ in 0..header.question_count {
        let question = parse_question(packet, offset)?;
        offset = question.next_offset;
        questions.push(question);
    }

    let record_capacity = header.total_records().min(packet.len() / 11);
    let mut records = Vec::with_capacity(record_capacity);
    for _ in 0..header.total_records() {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        records.push(record);
    }
    Ok((header, questions, records, offset))
}
