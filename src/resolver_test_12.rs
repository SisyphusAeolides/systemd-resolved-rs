#[cfg(test)]
mod test_12_edns_feature_downgrade {
    use super::*;
    use crate::wire::LocalRecord;

    #[test]
    fn rcode_probe_downgrades_and_persists_plain_dns() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("mock DNS timeout");
        let server_address = socket.local_addr().expect("mock DNS address");

        let server = thread::spawn(move || {
            for exchange_index in 0..4 {
                let mut buffer = [0; 2048];
                let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
                let query = &buffer[..length];
                let opt = edns::inspect_opt(query).expect("query OPT");

                let response = match exchange_index {
                    0 => {
                        let opt = opt.expect("DNSSEC-OK OPT");
                        assert!(opt.dnssec_ok());
                        assert!(opt.advertises_rfc6975());
                        let response = error_response(query, RCODE_FORMERR);
                        edns::add_test_response_opt(&response, 0, true)
                            .expect("FORMERR response with OPT")
                    }
                    1 => {
                        let opt = opt.expect("EDNS0 OPT");
                        assert!(!opt.dnssec_ok());
                        assert!(!opt.advertises_rfc6975());
                        let response = error_response(query, RCODE_FORMERR);
                        edns::add_test_response_opt(&response, 0, false)
                            .expect("FORMERR response with OPT")
                    }
                    2 | 3 => {
                        assert!(opt.is_none());
                        local_response(
                            query,
                            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 80))],
                            30,
                        )
                        .expect("mock A response")
                    }
                    _ => unreachable!(),
                };
                socket
                    .send_to(&response, peer)
                    .expect("mock DNS response");
            }
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::AllowDowngrade,
            ..Config::default()
        });

        for (id, name) in [(0x7001, "first.example"), (0x7002, "second.example")] {
            let query = make_query(name, TYPE_A, id).expect("client query");
            let response = resolver
                .query(&query, QueryMode::Full)
                .expect("resolver response");
            let records =
                extract_address_records(&response, Some(2)).expect("address records");
            assert_eq!(
                records.addresses,
                vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80))]
            );
        }

        server.join().expect("mock DNS thread");
    }

    #[test]
    fn strict_dnssec_rejects_a_missing_opt_response() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");
        let server_address = socket.local_addr().expect("mock DNS address");

        let server = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
            let query = &buffer[..length];
            let opt = edns::inspect_opt(query)
                .expect("query OPT")
                .expect("DNSSEC-OK OPT");
            assert!(opt.dnssec_ok());
            let response = local_response(
                query,
                &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 81))],
                30,
            )
            .expect("mock A response");
            socket
                .send_to(&response, peer)
                .expect("mock DNS response");
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::Yes,
            ..Config::default()
        });
        let query = make_query("strict.example", TYPE_A, 0x7003).expect("query");
        let error = resolver
            .query(&query, QueryMode::Full)
            .expect_err("strict DNSSEC must reject missing OPT");
        assert!(matches!(error, ResolveError::Protocol(_)));
        server.join().expect("mock DNS thread");
    }

    fn error_response(query: &[u8], rcode: u16) -> Vec<u8> {
        let end = wire::question_end(query).expect("question end");
        let mut response = query[..end].to_vec();
        let query_flags = u16::from_be_bytes([query[2], query[3]]);
        let flags = (query_flags & 0x0100) | 0x8000 | 0x0080 | rcode;
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response[6..12].fill(0);
        response
    }
}
