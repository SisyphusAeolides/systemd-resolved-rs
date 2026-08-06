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

    #[test]
    fn service_records_are_extracted() {
        let query = make_query("_demo._tcp.example", TYPE_SRV, 0x4242).expect("query");
        let question_end = question_end(&query).expect("question end");
        let mut response = query[..question_end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&2u16.to_be_bytes());

        let target = encode_name("host.example").expect("target");
        let srv_length = u16::try_from(6 + target.len()).expect("SRV length");
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_SRV.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&120u32.to_be_bytes());
        response.extend_from_slice(&srv_length.to_be_bytes());
        response.extend_from_slice(&10u16.to_be_bytes());
        response.extend_from_slice(&20u16.to_be_bytes());
        response.extend_from_slice(&8080u16.to_be_bytes());
        response.extend_from_slice(&target);

        let txt = b"path=/";
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_TXT.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&120u32.to_be_bytes());
        response.extend_from_slice(
            &u16::try_from(txt.len() + 1)
                .expect("TXT length")
                .to_be_bytes(),
        );
        response.push(u8::try_from(txt.len()).expect("TXT item length"));
        response.extend_from_slice(txt);

        let records = extract_service_records(&response).expect("service records");
        assert_eq!(
            records.srv,
            vec![SrvRecord {
                priority: 10,
                weight: 20,
                port: 8080,
                target: read_name(&target, 0).expect("target name").0,
            }]
        );
        assert_eq!(records.txt, vec![txt.to_vec()]);
    }

    #[test]
    fn malformed_txt_record_is_rejected() {
        let query = make_query("_demo._tcp.example", TYPE_TXT, 0x4243).expect("query");
        let question_end = question_end(&query).expect("question end");
        let mut response = query[..question_end].to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | FLAG_RD).to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_TXT.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&120u32.to_be_bytes());
        response.extend_from_slice(&2u16.to_be_bytes());
        response.extend_from_slice(&[5, b'x']);

        assert_eq!(
            extract_service_records(&response),
            Err(WireError::InvalidRecord)
        );
    }

}
