#[cfg(test)]
mod test_03_synthetic_and_parallel_scopes {
    use super::*;
    use crate::routing::ScopeKind;
    use crate::wire::LocalRecord;
    use std::sync::{Arc, Barrier};

    #[test]
    fn synthetic_answers_do_not_depend_on_reading_etc_hosts() {
        let config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            read_etc_hosts: false,
            ..Config::default()
        };
        let lookup = Resolver::new(config)
            .lookup_name("localhost", 2)
            .expect("synthetic lookup");
        assert_eq!(lookup.addresses, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn fragmented_edns_udp_retries_over_tcp() {
        assert!(udp_requires_tcp_retry(false, 1280, FeatureLevel::Edns0));
        assert!(udp_requires_tcp_retry(
            false,
            1280,
            FeatureLevel::DnssecOk
        ));
        assert!(!udp_requires_tcp_retry(false, 1280, FeatureLevel::Udp));
        assert!(udp_requires_tcp_retry(true, 0, FeatureLevel::Udp));
    }

    #[test]
    fn equivalent_scopes_dispatch_queries_in_parallel() {
        let first_socket = UdpSocket::bind("127.0.0.1:0").expect("first mock DNS bind");
        let second_socket = UdpSocket::bind("127.0.0.1:0").expect("second mock DNS bind");
        let first_server = first_socket.local_addr().expect("first mock DNS address");
        let second_server = second_socket.local_addr().expect("second mock DNS address");
        for socket in [&first_socket, &second_socket] {
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("mock DNS timeout");
        }

        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = Arc::clone(&barrier);
        let first_thread = thread::spawn(move || {
            reply_after_both_scopes_arrive(
                &first_socket,
                first_barrier.as_ref(),
                Ipv4Addr::new(192, 0, 2, 21),
            );
        });
        let second_thread = thread::spawn(move || {
            reply_after_both_scopes_arrive(
                &second_socket,
                barrier.as_ref(),
                Ipv4Addr::new(192, 0, 2, 22),
            );
        });

        let resolver = Resolver::new(Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let scopes = vec![
            RouteScope {
                kind: ScopeKind::Link(2),
                servers: vec![first_server],
            },
            RouteScope {
                kind: ScopeKind::Link(3),
                servers: vec![second_server],
            },
        ];
        let query = make_query("parallel.example", TYPE_A, 0x7200).expect("client query");
        let started = Instant::now();
        let (response, winning_server) = resolver
            .query_scopes(&scopes, &query)
            .expect("parallel scoped query");
        assert!(started.elapsed() < Duration::from_millis(750));
        assert!(winning_server == first_server || winning_server == second_server);

        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert!(records.addresses.iter().any(|address| {
            matches!(
                address,
                IpAddr::V4(address)
                    if *address == Ipv4Addr::new(192, 0, 2, 21)
                        || *address == Ipv4Addr::new(192, 0, 2, 22)
            )
        }));

        first_thread.join().expect("first mock DNS thread");
        second_thread.join().expect("second mock DNS thread");
    }

    #[test]
    fn localhost_upstream_is_not_cached_by_default() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");
        let server = socket.local_addr().expect("mock DNS address");
        let server_thread = thread::spawn(move || {
            for _ in 0..2 {
                reply_once(&socket, Ipv4Addr::new(192, 0, 2, 31));
            }
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let first = make_query("local-cache.example", TYPE_A, 0x7300).expect("first query");
        resolver
            .query(&first, QueryMode::Full)
            .expect("first response");
        assert!(resolver.cache.is_empty());

        let second = make_query("local-cache.example", TYPE_A, 0x7301).expect("second query");
        resolver
            .query(&second, QueryMode::Full)
            .expect("second response");
        assert!(resolver.cache.is_empty());
        server_thread.join().expect("mock DNS thread");
    }

    #[test]
    fn cache_from_localhost_allows_explicit_local_caching() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");
        let server = socket.local_addr().expect("mock DNS address");
        let server_thread = thread::spawn(move || {
            reply_once(&socket, Ipv4Addr::new(192, 0, 2, 32));
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            cache_from_localhost: true,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let first = make_query("local-cache.example", TYPE_A, 0x7400).expect("first query");
        resolver
            .query(&first, QueryMode::Full)
            .expect("first response");
        assert_eq!(resolver.cache.len(), 1);

        let second = make_query("local-cache.example", TYPE_A, 0x7401).expect("second query");
        let response = resolver
            .query(&second, QueryMode::Full)
            .expect("cached response");
        assert_eq!(&response[..2], &0x7401u16.to_be_bytes());
        server_thread.join().expect("mock DNS thread");
    }

    fn reply_after_both_scopes_arrive(socket: &UdpSocket, barrier: &Barrier, address: Ipv4Addr) {
        let mut buffer = [0; 2048];
        let (length, peer) = socket.recv_from(&mut buffer).expect("mock scoped query");
        barrier.wait();
        let response = local_response(&buffer[..length], &[LocalRecord::A(address)], 30)
            .expect("mock scoped response");
        socket
            .send_to(&response, peer)
            .expect("mock scoped response send");
    }

    fn reply_once(socket: &UdpSocket, address: Ipv4Addr) {
        let mut buffer = [0; 2048];
        let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
        let response = local_response(&buffer[..length], &[LocalRecord::A(address)], 30)
            .expect("mock DNS response");
        socket
            .send_to(&response, peer)
            .expect("mock DNS response send");
    }
}
