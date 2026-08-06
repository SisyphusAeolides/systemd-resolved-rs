#[cfg(test)]
mod test_10_proxy_mode_bypasses_local_synthesis {
    use super::*;

    #[test]
    fn proxy_mode_bypasses_local_synthesis() {
        let mut config = Config::default();
        config.upstreams.clear();
        config.fallback_upstreams.clear();
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_A, 55).expect("query");
        assert!(matches!(
            resolver.query(&query, QueryMode::Proxy),
            Err(ResolveError::NoNameServers)
        ));
    }
}
