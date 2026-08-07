#[cfg(test)]
mod test_18_servfail_ede {
    use super::*;
    use crate::wire::LocalRecord;

    #[test]
    fn servfail_retries_once_before_lowering_features() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        let server_address = socket.local_addr().expect("mock DNS address");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");

        let server = thread::spawn(move || {
            for exchange_index in 0..3 {
                let mut buffer = [0; 2048];
                let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
                let query = &buffer[..length];
                let opt = edns::inspect_opt(query)
                    .expect("query OPT")
                    .expect("EDNS query");
                let response = match exchange_index {
                    0 | 1 => {
                        assert!(opt.dnssec_ok());
                        let response = error_response(query, RCODE_SERVFAIL);
                        edns::add_test_response_opt(&response, 0, true)
                            .expect("SERVFAIL response")
                    }
                    2 => {
                        assert!(!opt.dnssec_ok());
                        let response = local_response(
                            query,
                            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 72))],
                            30,
                        )
                        .expect("successful response");
                        edns::add_test_response_opt(&response, 0, false)
                            .expect("successful EDNS response")
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
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::AllowDowngrade,
            ..Config::default()
        });
        let query = make_query("servfail.example", TYPE_A, 0x7400).expect("client query");
        let response = resolver
            .query(&query, QueryMode::Full)
            .expect("resolver response");
        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 72))]
        );
        server.join().expect("mock DNS thread");
    }

    #[test]
    fn ede_not_ready_retries_without_feature_downgrade() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        let server_address = socket.local_addr().expect("mock DNS address");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");

        let server = thread::spawn(move || {
            for exchange_index in 0..2 {
                let mut buffer = [0; 2048];
                let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
                let query = &buffer[..length];
                let opt = edns::inspect_opt(query)
                    .expect("query OPT")
                    .expect("DNSSEC query");
                assert!(opt.dnssec_ok());
                let response = if exchange_index == 0 {
                    add_ede_opt(&error_response(query, RCODE_SERVFAIL), true, EDE_NOT_READY)
                } else {
                    let response = local_response(
                        query,
                        &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 73))],
                        30,
                    )
                    .expect("successful response");
                    edns::add_test_response_opt(&response, 0, true)
                        .expect("successful EDNS response")
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
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::AllowDowngrade,
            ..Config::default()
        });
        let query = make_query("not-ready.example", TYPE_A, 0x7401).expect("client query");
        let mut budget = DnsAttemptBudget::new();
        let response = resolver
            .exchange_with_features(server_address, &query, &mut budget)
            .expect("resolver response");
        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 73))]
        );
        assert_eq!(budget.attempts(), 2);
        server.join().expect("mock DNS thread");
    }

    #[test]
    fn detailed_servfail_does_not_degrade_edns_features() {
        const EDE_NO_REACHABLE_AUTHORITY: u16 = 22;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        let server_address = socket.local_addr().expect("mock DNS address");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");

        let server = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
            let query = &buffer[..length];
            let opt = edns::inspect_opt(query)
                .expect("query OPT")
                .expect("DNSSEC query");
            assert!(opt.dnssec_ok());
            let response = add_ede_opt(
                &error_response(query, RCODE_SERVFAIL),
                true,
                EDE_NO_REACHABLE_AUTHORITY,
            );
            socket
                .send_to(&response, peer)
                .expect("mock DNS response");
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::AllowDowngrade,
            ..Config::default()
        });
        let query = make_query("ede-servfail.example", TYPE_A, 0x7402).expect("client query");
        let mut budget = DnsAttemptBudget::new();
        let response = resolver
            .exchange_with_features(server_address, &query, &mut budget)
            .expect("SERVFAIL response");
        assert_eq!(Header::parse(&response).expect("response header").response_code(), 2);
        assert_eq!(budget.attempts(), 1);

        let mut states = resolver.states();
        let state = states.get_mut(&server_address).expect("server state");
        assert_eq!(
            state
                .features
                .possible_level(FeatureLevel::DnssecOk, Instant::now()),
            FeatureLevel::DnssecOk
        );
        drop(states);
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

    fn add_ede_opt(packet: &[u8], dnssec_ok: bool, ede_code: u16) -> Vec<u8> {
        let mut response = packet.to_vec();
        response[10..12].copy_from_slice(&1_u16.to_be_bytes());
        response.push(0);
        response.extend_from_slice(&41_u16.to_be_bytes());
        response.extend_from_slice(&edns::DEFAULT_UDP_PAYLOAD_SIZE.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&(if dnssec_ok { 0x8000_u16 } else { 0 }).to_be_bytes());
        response.extend_from_slice(&6_u16.to_be_bytes());
        response.extend_from_slice(&EDNS_OPTION_EXTENDED_ERROR.to_be_bytes());
        response.extend_from_slice(&2_u16.to_be_bytes());
        response.extend_from_slice(&ede_code.to_be_bytes());
        response
    }
}
