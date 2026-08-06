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
                first_socket,
                first_barrier,
                Ipv4Addr::new(192, 0, 2, 21),
            );
        });
        let second_thread = thread::spawn(move || {
            reply_after_both_scopes_arrive(
                second_socket,
                barrier,
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
        let response = resolver
            .query_scopes(&scopes, &query)
            .expect("parallel scoped query");
        assert!(started.elapsed() < Duration::from_millis(750));

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

    fn reply_after_both_scopes_arrive(
        socket: UdpSocket,
        barrier: Arc<Barrier>,
        address: Ipv4Addr,
    ) {
        let mut buffer = [0; 2048];
        let (length, peer) = socket.recv_from(&mut buffer).expect("mock scoped query");
        barrier.wait();
        let response = local_response(&buffer[..length], &[LocalRecord::A(address)], 30)
            .expect("mock scoped response");
        socket
            .send_to(&response, peer)
            .expect("mock scoped response send");
    }
}
