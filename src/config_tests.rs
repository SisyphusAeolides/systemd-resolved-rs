// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fallback_dns_matches_pinned_upstream_order() {
        let config = Config::default();
        let expected: Vec<SocketAddr> = [
            "1.1.1.1:53",
            "8.8.8.8:53",
            "9.9.9.9:53",
            "1.0.0.1:53",
            "8.8.4.4:53",
            "149.112.112.112:53",
            "[2606:4700:4700::1111]:53",
            "[2001:4860:4860::8888]:53",
            "[2620:fe::fe]:53",
            "[2606:4700:4700::1001]:53",
            "[2001:4860:4860::8844]:53",
            "[2620:fe::9]:53",
        ]
        .into_iter()
        .map(|server| server.parse().expect("fallback server"))
        .collect();
        assert_eq!(config.fallback_upstreams, expected);
    }

    #[test]
    fn parses_core_resolved_settings() {
        let mut config = Config::default();
        config
            .apply_text(
                "[Resolve]\n\
                 DNS=192.0.2.53 2001:db8::53\n\
                 Domains=example.test ~corp.test\n\
                 Cache=no\n\
                 DNSCacheSize=128\n\
                 ReadEtcHosts=no\n\
                 ReadStaticRecords=no\n",
            )
            .expect("configuration");
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.domains.len(), 2);
        assert!(!config.cache);
        assert_eq!(config.cache_size, 128);
        assert!(!config.read_etc_hosts);
        assert!(!config.read_static_records);
    }

    #[test]
    fn empty_assignment_resets_a_list() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nDNS=192.0.2.53\nDNS=\n")
            .expect("configuration");
        assert!(config.upstreams.is_empty());
    }

    #[test]
    fn local_stub_is_not_an_upstream() {
        let config = Config {
            upstreams: vec![
                "127.0.0.53:53".parse().expect("stub"),
                "192.0.2.53:53".parse().expect("uplink"),
            ],
            ..Config::default()
        };
        assert_eq!(config.effective_upstreams().len(), 1);
    }

    #[test]
    fn tracks_explicit_dns_and_domain_assignments() {
        let mut config = Config::default();
        let assignments = config
            .apply_text_tracking("[Resolve]\nDNS=\nDomains=example.test\n")
            .expect("tracked configuration");
        assert_eq!(
            assignments,
            ConfigAssignments {
                dns: true,
                domains: true,
            }
        );
    }

    #[test]
    fn reads_dns_and_search_domain_credentials() {
        let directory = temporary_credential_directory("reads");
        fs::create_dir_all(&directory).expect("credential directory");
        fs::write(directory.join("network.dns"), "192.0.2.53 2001:db8::53\n")
            .expect("DNS credential");
        fs::write(
            directory.join("network.search_domains"),
            "example.test ~corp.test\n",
        )
        .expect("domain credential");

        let mut config = Config::default();
        config.upstreams.clear();
        assert!(apply_credentials(&mut config, &directory));
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(
            config.domains,
            vec![
                Domain {
                    name: "example.test".to_owned(),
                    route_only: false,
                },
                Domain {
                    name: "corp.test".to_owned(),
                    route_only: true,
                },
            ]
        );
        fs::remove_dir_all(directory).expect("remove credential directory");
    }

    #[test]
    fn empty_credentials_are_present_and_reset_lists() {
        let directory = temporary_credential_directory("empty");
        fs::create_dir_all(&directory).expect("credential directory");
        fs::write(directory.join("network.dns"), "").expect("empty DNS credential");
        fs::write(directory.join("network.search_domains"), "")
            .expect("empty domain credential");

        let mut config = Config::default();
        config.upstreams.push("192.0.2.53:53".parse().expect("server"));
        config.domains.push(Domain {
            name: "example.test".to_owned(),
            route_only: false,
        });
        assert!(apply_credentials(&mut config, &directory));
        assert!(config.upstreams.is_empty());
        assert!(config.domains.is_empty());
        fs::remove_dir_all(directory).expect("remove credential directory");
    }

    #[test]
    fn missing_credentials_do_not_suppress_resolv_conf_discovery() {
        let directory = temporary_credential_directory("missing");
        fs::create_dir_all(&directory).expect("credential directory");
        let mut config = Config::default();
        assert!(!apply_credentials(&mut config, &directory));
        fs::remove_dir_all(directory).expect("remove credential directory");
    }

    fn temporary_credential_directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "systemd-resolved-rs-credentials-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        directory
    }
}
