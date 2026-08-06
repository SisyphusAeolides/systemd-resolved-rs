// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trip() {
        let packet = make_query("Example.COM.", TYPE_A, 0x1234).expect("query");
        validate(&packet, false).expect("valid query");
        assert_eq!(first_question(&packet).expect("question").name.text(), "Example.COM");
    }

    #[test]
    fn compression_cycle_is_rejected() {
        let mut packet = vec![0; DNS_HEADER_LEN];
        packet[4..6].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert_eq!(validate(&packet, false), Err(WireError::CompressionLoop));
    }

    #[test]
    fn servfail_preserves_the_question() {
        let query = make_query("example.com", TYPE_AAAA, 44).expect("query");
        let response = servfail_for(&query).expect("response");
        assert_eq!(Header::parse(&response).expect("header").response_code(), 2);
        response_matches(&query, &response).expect("matching response");
    }

    #[test]
    fn local_a_response_is_extractable() {
        let query = make_query("localhost", TYPE_A, 9).expect("query");
        let response = local_response(
            &query,
            &[LocalRecord::A(Ipv4Addr::LOCALHOST)],
            0,
        )
        .expect("response");
        assert_eq!(
            extract_addresses(&response, Some(2)).expect("addresses"),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    #[test]
    fn reverse_names_round_trip() {
        let addresses = [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6("2001:db8::1".parse().expect("IPv6")),
        ];
        for address in addresses {
            assert_eq!(parse_reverse_name(&reverse_name(address)), Some(address));
        }
    }
}
