#[cfg(test)]
mod test_03_synthetic_answers_do_not_depend_on_reading_etc_hosts {
    use super::*;

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

}
