// SPDX-License-Identifier: LGPL-2.1-or-later
fn apply_refuse_record_types(destination: &mut BTreeSet<u16>, value: &str) {
    if value.is_empty() {
        destination.clear();
        return;
    }
    for token in value.split_whitespace() {
        if let Some(rr_type) = dns_record_type_from_string(token) {
            destination.insert(rr_type);
        }
    }
}

fn dns_record_type_from_string(value: &str) -> Option<u16> {
    if value.len() > 4 && value[..4].eq_ignore_ascii_case("TYPE") {
        return value[4..].parse::<u16>().ok();
    }

    Some(match value {
        "A" => 1,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "WKS" => 11,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "NSAP" => 22,
        "NSAP-PTR" => 23,
        "SIG" => 24,
        "KEY" => 25,
        "PX" => 26,
        "GPOS" => 27,
        "AAAA" => 28,
        "LOC" => 29,
        "NXT" => 30,
        "EID" => 31,
        "NIMLOC" => 32,
        "SRV" => 33,
        "ATMA" => 34,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "A6" => 38,
        "DNAME" => 39,
        "SINK" => 40,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC3" => 50,
        "NSEC3PARAM" => 51,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "HIP" => 55,
        "NINFO" => 56,
        "RKEY" => 57,
        "TALINK" => 58,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "UINFO" => 100,
        "UID" => 101,
        "GID" => 102,
        "UNSPEC" => 103,
        "NID" => 104,
        "L32" => 105,
        "L64" => 106,
        "LP" => 107,
        "EUI48" => 108,
        "EUI64" => 109,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "MAILB" => 253,
        "MAILA" => 254,
        "ANY" => 255,
        "URI" => 256,
        "CAA" => 257,
        "AVC" => 258,
        "DOA" => 259,
        "AMTRELAY" => 260,
        "RESINFO" => 261,
        "TA" => 32768,
        "DLV" => 32769,
        _ => return None,
    })
}

#[cfg(test)]
mod record_type_tests {
    use super::*;

    #[test]
    fn parses_named_and_rfc3597_record_types() {
        assert_eq!(dns_record_type_from_string("AAAA"), Some(28));
        assert_eq!(dns_record_type_from_string("SRV"), Some(33));
        assert_eq!(dns_record_type_from_string("TYPE65400"), Some(65400));
        assert_eq!(dns_record_type_from_string("type65400"), Some(65400));
        assert_eq!(dns_record_type_from_string("TYPE65536"), None);
        assert_eq!(dns_record_type_from_string("NOT-A-TYPE"), None);
    }

    #[test]
    fn empty_refuse_assignment_clears_the_set() {
        let mut types = BTreeSet::from([1, 28]);
        apply_refuse_record_types(&mut types, "");
        assert!(types.is_empty());
    }

    #[test]
    fn invalid_refuse_tokens_are_ignored() {
        let mut types = BTreeSet::new();
        apply_refuse_record_types(&mut types, "A bogus TYPE65400");
        assert_eq!(types, BTreeSet::from([1, 65400]));
    }
}
