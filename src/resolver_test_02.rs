#[cfg(test)]
mod test_02_lookup_name_follows_cname_and_ignores_unrelated_addresses {
    use super::*;

    fn append_test_answer(packet: &mut Vec<u8>, owner: &[u8], rr_type: u16, rdata: &[u8]) {
        packet.extend_from_slice(owner);
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("test RDATA length")
                .to_be_bytes(),
        );
        packet.extend_from_slice(rdata);
    }

    #[test]
    fn lookup_name_follows_cname_and_ignores_unrelated_addresses() {
        use crate::wire::{encode_name, question_end, TYPE_CNAME};
        use std::thread;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = socket.recv_from(&mut buffer).expect("receive query");
            let query = &buffer[..length];
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&3u16.to_be_bytes());
            response[8..12].fill(0);

            let canonical = encode_name("real.example.test").expect("canonical name");
            append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_CNAME, &canonical);
            append_test_answer(
                &mut response,
                &encode_name("unrelated.example.test").expect("unrelated owner"),
                TYPE_A,
                &[203, 0, 113, 9],
            );
            append_test_answer(&mut response, &canonical, TYPE_A, &[192, 0, 2, 42]);
            socket.send_to(&response, peer).expect("send DNS response");
        });

        let config = Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let lookup = Resolver::new(config)
            .lookup_name("alias.example.test", 2)
            .expect("CNAME lookup");
        worker.join().expect("test DNS worker");

        assert_eq!(lookup.canonical_name, "real.example.test");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))]
        );
    }

}
