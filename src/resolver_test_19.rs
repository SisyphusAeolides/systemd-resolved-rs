// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod test_19_refuse_record_types {
    use super::*;

    #[test]
    fn configured_type_is_refused_before_local_synthesis() {
        let mut config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            ..Config::default()
        };
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA SRV TXT\n")
            .expect("refuse record type configuration");
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_AAAA, 0x7500).expect("AAAA query");
        let response = resolver.query(&query, QueryMode::Full).expect("REFUSED reply");
        let header = Header::parse(&response).expect("response header");
        assert_eq!(header.response_code(), 5);
        assert_eq!(header.answer_count, 0);
        assert_eq!(&response[..2], &0x7500u16.to_be_bytes());
    }

    #[test]
    fn high_level_record_api_preserves_refused_rcode() {
        let mut config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            ..Config::default()
        };
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA\n")
            .expect("refuse record type configuration");
        let resolver = Resolver::new(config);
        let error = resolver
            .resolve_record("localhost", TYPE_AAAA)
            .expect_err("AAAA must be refused");
        assert!(matches!(
            error,
            ResolveError::DnsError { rcode: 5, ref query } if query == "localhost"
        ));
        assert_eq!(error.varlink_id(), "io.systemd.Resolve.DNSError");
    }

    #[test]
    fn unrefused_type_still_uses_local_synthesis() {
        let mut config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            ..Config::default()
        };
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA SRV TXT\n")
            .expect("refuse record type configuration");
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_A, 0x7501).expect("A query");
        let response = resolver.query(&query, QueryMode::Full).expect("A reply");
        let header = Header::parse(&response).expect("response header");
        assert_eq!(header.response_code(), 0);
        assert!(header.answer_count > 0);
    }

    #[test]
    fn empty_assignment_clears_refused_types() {
        let mut config = Config::default();
        config
            .apply_text(
                "[Resolve]\n\
                 RefuseRecordTypes=AAAA TYPE65400\n\
                 RefuseRecordTypes=\n",
            )
            .expect("refuse record type configuration");
        assert!(config.refuse_record_types.is_empty());
    }
}
