// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::many_single_char_names)]

use resolved::json::Value;
use std::collections::BTreeMap;
use std::error::Error;
use std::io;
use std::path::Path;

const CLASS_IN: u16 = 1;
const TYPE_TLSA: u16 = 52;
const TYPE_OPENPGPKEY: u16 = 61;
const DNS_LABEL_MAX: usize = 63;
const DNS_NAME_MAX: usize = 253;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalRecord {
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TlsaQuery {
    owner: String,
    target: String,
}

pub(super) fn openpgp(socket: &Path, inputs: &[String]) -> Result<(), Box<dyn Error>> {
    if inputs.is_empty() {
        return Err("openpgp requires at least one email address".into());
    }

    let mut failures = 0usize;
    for email in inputs {
        let result = (|| {
            let owner = openpgp_owner(email)?;
            let records = resolve_records(socket, &owner, TYPE_OPENPGPKEY)?;
            for record in records {
                println!("{owner} IN OPENPGPKEY {}", encode_base64(&record.rdata));
            }
            Ok::<(), Box<dyn Error>>(())
        })();
        if let Err(error) = result {
            eprintln!("{email}: {error}");
            failures += 1;
        }
    }
    finish_many("OPENPGPKEY", failures)
}

pub(super) fn tlsa(socket: &Path, inputs: &[String]) -> Result<(), Box<dyn Error>> {
    let queries = tlsa_queries(inputs)?;
    let mut failures = 0usize;
    for query in queries {
        let result = (|| {
            let records = resolve_records(socket, &query.owner, TYPE_TLSA)?;
            for record in records {
                let [usage, selector, matching_type, association @ ..] = record.rdata.as_slice()
                else {
                    return Err(invalid_data("TLSA record is shorter than three octets").into());
                };
                println!(
                    "{} IN TLSA {} {} {} {}",
                    query.owner,
                    usage,
                    selector,
                    matching_type,
                    encode_hex(association)
                );
            }
            Ok::<(), Box<dyn Error>>(())
        })();
        if let Err(error) = result {
            eprintln!("{}: {error}", query.target);
            failures += 1;
        }
    }
    finish_many("TLSA", failures)
}

fn finish_many(operation: &str, failures: usize) -> Result<(), Box<dyn Error>> {
    if failures == 0 {
        Ok(())
    } else {
        Err(format!("{failures} {operation} lookup operation(s) failed").into())
    }
}

fn resolve_records(
    socket: &Path,
    owner: &str,
    rr_type: u16,
) -> Result<Vec<CanonicalRecord>, Box<dyn Error>> {
    let reply = super::call(
        socket,
        "io.systemd.Resolve.ResolveRecord",
        Value::object([
            ("ifindex", Value::Number(0)),
            ("name", Value::String(owner.to_owned())),
            ("class", Value::Number(i128::from(CLASS_IN))),
            ("type", Value::Number(i128::from(rr_type))),
            ("flags", Value::Number(0)),
        ]),
    )?;
    let parameters = super::reply_parameters(&reply)?;
    let values = parameters
        .get("rrs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("ResolveRecord reply has no record array"))?;

    let mut records = Vec::with_capacity(values.len());
    for value in values {
        let raw = value
            .get("raw")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_data("ResolveRecord reply has no raw record"))?;
        let record = parse_canonical_record(&decode_base64(raw)?)?;
        if record.rr_type != rr_type || record.class != CLASS_IN {
            return Err(
                invalid_data("ResolveRecord reply changed the requested type or class").into(),
            );
        }
        records.push(record);
    }
    if records.is_empty() {
        return Err("ResolveRecord reply contained no records".into());
    }
    Ok(records)
}

fn openpgp_owner(email: &str) -> Result<String, Box<dyn Error>> {
    let Some(separator) = email.rfind('@') else {
        return Err(format!("invalid email address: {email}").into());
    };
    let local = canonical_local_part(&email[..separator])?;
    let domain = canonical_domain(&email[separator + 1..])?;
    let digest = sha256(local.as_bytes());
    Ok(format!(
        "{}._openpgpkey.{domain}",
        encode_hex(&digest[..28])
    ))
}

fn canonical_local_part(input: &str) -> Result<String, Box<dyn Error>> {
    if input.is_empty() {
        return Err("email local-part is empty".into());
    }
    if input.starts_with('"') {
        if input.len() < 2 || !input.ends_with('"') {
            return Err("unterminated quoted email local-part".into());
        }
        let mut output = String::new();
        let mut escaped = false;
        for character in input[1..input.len() - 1].chars() {
            if escaped {
                if character == '\r' || character == '\n' || character == '\0' {
                    return Err("invalid quoted email local-part".into());
                }
                output.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character.is_control() {
                return Err("invalid quoted email local-part".into());
            } else {
                output.push(character);
            }
        }
        if escaped || output.is_empty() {
            return Err("invalid quoted email local-part".into());
        }
        return Ok(output);
    }

    if input.starts_with('.')
        || input.ends_with('.')
        || input.contains("..")
        || input.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(
                    character,
                    '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | ',' | '"' | '\\'
                )
        })
    {
        return Err("invalid unquoted email local-part".into());
    }
    Ok(input.to_owned())
}

fn canonical_domain(input: &str) -> Result<String, Box<dyn Error>> {
    let input = input.trim_end_matches('.');
    if input.is_empty() {
        return Err("email or TLSA domain is empty".into());
    }

    #[cfg(feature = "idna-name")]
    let domain = idna::domain_to_ascii(input)
        .map_err(|_| invalid_data("domain cannot be converted with IDNA"))?;
    #[cfg(not(feature = "idna-name"))]
    let domain = {
        if !input.is_ascii() {
            return Err("internationalized domains require the idna-name feature".into());
        }
        input.to_owned()
    };

    let domain = domain.to_ascii_lowercase();
    if domain.len() > DNS_NAME_MAX
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > DNS_LABEL_MAX
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(format!("invalid DNS domain: {input}").into());
    }
    Ok(domain)
}

fn tlsa_queries(inputs: &[String]) -> Result<Vec<TlsaQuery>, Box<dyn Error>> {
    if inputs.is_empty() {
        return Err("tlsa requires at least one domain".into());
    }
    let mut family = "tcp";
    let mut targets = inputs;
    if matches!(inputs[0].as_str(), "tcp" | "udp" | "sctp") {
        family = inputs[0].as_str();
        targets = &inputs[1..];
    }
    if targets.is_empty() {
        return Err("tlsa requires at least one domain after the protocol family".into());
    }

    targets
        .iter()
        .map(|target| {
            let (domain, port) = tlsa_target(target)?;
            Ok(TlsaQuery {
                owner: format!("_{port}._{family}.{domain}"),
                target: target.clone(),
            })
        })
        .collect()
}

fn tlsa_target(input: &str) -> Result<(String, u16), Box<dyn Error>> {
    let (domain, port) = match input.rsplit_once(':') {
        Some((domain, port)) => {
            if domain.is_empty() || port.is_empty() {
                return Err(format!("invalid TLSA target: {input}").into());
            }
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("invalid TLSA port in {input}"))?;
            if port == 0 {
                return Err(format!("invalid TLSA port in {input}").into());
            }
            (domain, port)
        }
        None => (input, 443),
    };
    Ok((canonical_domain(domain)?, port))
}

fn parse_canonical_record(input: &[u8]) -> Result<CanonicalRecord, io::Error> {
    let mut offset = 0usize;
    loop {
        let length = usize::from(
            *input
                .get(offset)
                .ok_or_else(|| invalid_data("record owner is truncated"))?,
         );
        offset = offset
            .checked_add(1)
            .ok_or_else(|| invalid_data("record owner offset overflow"))?;
        if length == 0 {
            break;
        }
        if length > DNS_LABEL_MAX || length & 0xc0 != 0 {
            return Err(invalid_data("record owner is not an uncompressed DNS name"));
        }
        offset = offset
            .checked_add(length)
            .filter(|end| *end <= input.len())
            .ok_or_else(|| invalid_data("record owner label is truncated"))?;
    }

    let fixed_end = offset
        .checked_add(10)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| invalid_data("record header is truncated"))?;
    let rr_type = read_u16(input, offset)?;
    let class = read_u16(input, offset + 2)?;
    let ttl = read_u32(input, offset + 4)?;
    let rdata_length = usize::from(read_u16(input, offset + 8)?);
    let end = fixed_end
        .checked_add(rdata_length)
        .filter(|end| *end == input.len())
        .ok_or_else(|| invalid_data("record RDATA length does not match the raw record"))?;
    Ok(CanonicalRecord {
        rr_type,
        class,
        ttl,
        rdata: input[fixed_end..end].to_vec(),
    })
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, io::Error> {
    let bytes: [u8; 2] = input
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_data("record is truncated"))?
        .try_into()
        .map_err(|_| invalid_data("record is truncated"))?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, io::Error> {
    let bytes: [u8; 4] = input
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_data("record is truncated")?
        .try_into()
        .map_err(|_| invalid_data("record is truncated"))?;
    Ok(u32::from_be_bytes(bytes))
}

fn decode_base64(input: &str) -> Result<Vec<u8>, io::Error> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err(invalid_data("invalid base64 record length"));
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    let block_count = bytes.len() / 4;
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == block_count;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' {
                return Err(invalid_data("invalid base64 padding"));
            }
            None
        } else {
            Some(base64_value(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            if !last {
                return Err(invalid_data("invalid base64 padding"));
            }
            None
        } else {
            Some(base64_value(chunk[3])?)
        };
        if c.is_none() && d.is_some() {
            return Err(invalid_data("invalid base64 padding"));
        }

        output.push((a << 2) | (b >> 4));
        if let Some(c) = c {
            output.push((b << 4) | (c >> 2));
            if let Some(d) = d {
                output.push((c << 6) | d);
            } else if c & 0x03 != 0 {
                return Err(invalid_data("non-canonical base64 padding"));
            }
        } else if b & 0x0f != 0 {
            return Err(invalid_data("non-canonical base64 padding"));
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, io::Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(invalid_data("invalid base64 character")),
    }
}

fn encode_base64(input: &[u8]) -> String {
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

fn encode_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[allow(clippy::needless_range_loop)]
fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut message = Vec::with_capacity(input.len().saturating_add(72));
    message.extend_from_slice(input);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for block in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(bytes.try_into().expect("four-byte SHA-256 word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let first = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (value, addition) in state.iter_mut().zip([a, b, c, d, e, f, g, h].into_iter()) {
            *value = value.wrapping_add(addition);
        }
    }

    let mut output = [0u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            encode_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn openpgp_owner_matches_rfc7929_example() {
        assert_eq!(
            openpgp_owner("hugh@example.com").unwrap(),
            "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com"
        );
    }

    #[test]
    fn openpgp_owner_preserves_local_part_case() {
        assert_ne!(
            openpgp_owner("Hugh@example.com").unwrap(),
            openpgp_owner("hugh@example.com").unwrap()
        );
    }

    #[test]
    fn quoted_local_part_is_unquoted_and_unescaped() {
        assert_eq!(
            openpgp_owner("\"h\\ugh\"@example.com").unwrap(),
            openpgp_owner("hugh@example.com").unwrap()
        );
    }

    #[test]
    fn constructs_default_and_explicit_tlsa_names() {
        assert_eq!(
            tlsa_queries(&["example.com".to_owned()]).unwrap(),
            vec![TlsaQuery {
                owner: "_443._tcp.example.com".to_owned(),
                target: "example.com".to_owned(),
            }]
        );
        assert_eq!(
            tlsa_queries(&["udp".to_owned(), "example.com:853".to_owned()]).unwrap(),
            vec![TlsaQuery {
                owner: "_853._udp.example.com".to_owned(),
                target: "example.com:853".to_owned(),
            }]
        );
    }

    #[test]
    fn base64_round_trip_is_strict() {
        for input in [b"".as_slice(), b"f", b"fo", b"foo", b"foobar"] {
            let encoded = encode_base64(input);
            if input.is_empty() {
                assert!(decode_base64(&encoded).is_err());
            } else {
                assert_eq!(decode_base64(&encoded).unwrap(), input);
            }
        }
        assert!(decode_base64("Zg=A").is_err());
        assert!(decode_base64("Zh==").is_err());
    }

    #[test]
    fn parses_canonical_raw_record() {
        let mut raw = vec![4, b'_', b'4', b'4', b'3', 4, b'_', b't', b'c', b'p'];
        raw.extend_from_slice(&[7]);
        raw.extend_from_slice(b"example");
        raw.extend_from_slice(&[3]);
        raw.extend_from_slice(b"com");
        raw.push(0);
        raw.extend_from_slice(&TYPE_TLSA.to_be_bytes());
        raw.extend_from_slice(&CLASS_IN.to_be_bytes());
        raw.extend_from_slice(&300u32.to_be_bytes());
        raw.extend_from_slice(&5u16.to_be_bytes());
        raw.extend_from_slice(&[3, 1, 1, 0xaa, 0xbb]);
        assert_eq!(
            parse_canonical_record(&raw).unwrap(),
            CanonicalRecord {
                rr_type: TYPE_TLSA,
                class: CLASS_IN,
                ttl: 300,
                rdata: vec![3, 1, 1, 0xaa, 0xbb],
            }
        );
    }
}
