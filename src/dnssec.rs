// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::wire::{dnskey_key_tag, parse_dnskey, parse_ds, ResourceRecord, WireError};
use std::error::Error;
use std::fmt;
use std::io;
use std::os::raw::{c_int, c_void};

extern "C" {
    fn resolved_dnssec_digest(
        digest_type: u8,
        data: *const c_void,
        length: usize,
        output: *mut u8,
        capacity: usize,
    ) -> c_int;
}

#[derive(Debug)]
pub enum DnssecError {
    Wire(WireError),
    Io(io::Error),
    UnsupportedDigest(u8),
}

impl fmt::Display for DnssecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::UnsupportedDigest(digest) => {
                write!(formatter, "unsupported DNSSEC DS digest type {digest}")
            }
        }
    }
}

impl Error for DnssecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::UnsupportedDigest(_) => None,
        }
    }
}

impl From<WireError> for DnssecError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<io::Error> for DnssecError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn dnskey_ds_digest(
    dnskey_record: &ResourceRecord,
    digest_type: u8,
) -> Result<Vec<u8>, DnssecError> {
    parse_dnskey(dnskey_record)?;
    let output_length = match digest_type {
        1 => 20,
        2 => 32,
        4 => 48,
        other => return Err(DnssecError::UnsupportedDigest(other)),
    };
    let mut input = Vec::with_capacity(
        dnskey_record.name.canonical_wire().len() + dnskey_record.rdata.len(),
    );
    input.extend_from_slice(dnskey_record.name.canonical_wire());
    input.extend_from_slice(&dnskey_record.rdata);
    let mut output = vec![0; output_length];
    // SAFETY: input and output are valid contiguous buffers for the duration of the digest call.
    let result = unsafe {
        resolved_dnssec_digest(
            digest_type,
            input.as_ptr().cast::<c_void>(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result).into());
    }
    let result = usize::try_from(result)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid DNSSEC digest length"))?;
    if result != output_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected DNSSEC digest length",
        )
        .into());
    }
    Ok(output)
}

pub fn ds_matches_dnskey(
    ds_record: &ResourceRecord,
    dnskey_record: &ResourceRecord,
) -> Result<bool, DnssecError> {
    let ds = parse_ds(ds_record)?;
    let dnskey = parse_dnskey(dnskey_record)?;
    if ds.algorithm != dnskey.algorithm || ds.key_tag != dnskey_key_tag(dnskey_record)? {
        return Ok(false);
    }
    Ok(ds.digest == dnskey_ds_digest(dnskey_record, ds.digest_type)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{encode_name, parse_record, CLASS_IN, TYPE_DNSKEY, TYPE_DS};

    fn record(owner: &str, rr_type: u16, rdata: &[u8]) -> ResourceRecord {
        let mut packet = encode_name(owner).expect("owner name");
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&60_u32.to_be_bytes());
        packet.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("RDATA length")
                .to_be_bytes(),
        );
        packet.extend_from_slice(rdata);
        parse_record(&packet, 0).expect("resource record")
    }

    #[test]
    fn dnskey_sha256_digest_uses_canonical_owner_wire() {
        let dnskey = record(
            "ExAmPlE.",
            TYPE_DNSKEY,
            &[0x01, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01],
        );
        let expected = [
            0x97, 0xf7, 0x14, 0x06, 0x59, 0xbf, 0xca, 0x21, 0xf9, 0xa4, 0xa9, 0x7c, 0xec,
            0xb2, 0x40, 0x0e, 0xa5, 0xcf, 0x99, 0x47, 0xc3, 0x7d, 0xdd, 0x62, 0x85, 0xe8,
            0xc5, 0xb0, 0x48, 0xc9, 0x59, 0x80,
        ];
        assert_eq!(dnskey_ds_digest(&dnskey, 2).expect("DS digest"), expected);
    }

    #[test]
    fn ds_match_checks_key_tag_algorithm_and_digest() {
        let dnskey = record(
            "example.",
            TYPE_DNSKEY,
            &[0x01, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01],
        );
        let digest = dnskey_ds_digest(&dnskey, 2).expect("DS digest");
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&dnskey_key_tag(&dnskey).expect("key tag").to_be_bytes());
        rdata.extend_from_slice(&[8, 2]);
        rdata.extend_from_slice(&digest);
        let ds = record("example.", TYPE_DS, &rdata);
        assert!(ds_matches_dnskey(&ds, &dnskey).expect("DS match"));

        let mut wrong = rdata;
        wrong[1] ^= 1;
        let ds = record("example.", TYPE_DS, &wrong);
        assert!(!ds_matches_dnskey(&ds, &dnskey).expect("DS mismatch"));
    }

    #[test]
    fn unsupported_ds_digest_is_explicit() {
        let dnskey = record(
            "example.",
            TYPE_DNSKEY,
            &[0x01, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01],
        );
        assert!(matches!(
            dnskey_ds_digest(&dnskey, 3),
            Err(DnssecError::UnsupportedDigest(3))
        ));
    }
}
